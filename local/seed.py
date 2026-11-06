# /// script
# requires-python = ">=3.13"
# dependencies = [
#   "psycopg[binary]==3.3.6",
# ]
# [tool.uv]
# exclude-newer = "2026-10-28T00:00:00Z"
# ///
"""The local seed (#182): what a person, or the journey test, needs to sign in to the local stack.

Run with `make seed` after `make up`. It writes, as the local server's superuser:

- the `local-keycloak` connection in `idp_connections`: the stack's Keycloak, standing in for the
  user pool (ADR-0016), which the API names in `OIDC_PROVIDER_NAME`;
- a tenant, with its policy;
- an admin and a member, each with a `user_identities` row bound to its Keycloak subject in
  local/keycloak/sft-realm.json, so both sign in through Keycloak as members do through Cognito;
- with `--suppress ADDRESS`, a suppression entry for that address in the tenant (#174), so a test
  can show `422 recipient_undeliverable`.

Every row has a fixed ID and is written with `ON CONFLICT DO NOTHING`, so the seed is idempotent:
run it again and nothing changes. It writes no audit events: the superuser is exempt from the
audit trigger and row-level security, like every seed of the test suite, and seeding isn't an
action of the service.

It runs only against the local stack: the URL must name the loopback address and the `sft`
database, and that database must hold the stack's roles and schema. Every credential here is
local-only and fake.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import os
import sys
from urllib.parse import urlsplit

import psycopg

DEFAULT_URL = "postgresql://sft:sft-local-only@127.0.0.1:5432/sft"
LOOPBACK = frozenset({"127.0.0.1", "localhost", "::1"})

TENANT_ID = "11111111-1111-4111-8111-111111111111"
TENANT_NAME = "Local Example Co"
CONNECTION_ID = "66666666-6666-4666-8666-666666666666"
PROVIDER = "local-keycloak"
ISSUER = "http://localhost:8180/realms/sft"
WEB_APP = "http://localhost:3000"

# Each user's ID is its Keycloak `username` (the ID token's `cognito:username`), and its identity's
# subject is the Keycloak user's own ID (`sub`): local/keycloak/sft-realm.json.
USERS = (
    {
        "role": "admin",
        "user_id": "44444444-4444-4444-8444-444444444444",
        "identity_id": "88888888-8888-4888-8888-888888888888",
        "subject": "55555555-5555-4555-8555-555555555555",
        "email": "dev.admin@example.com",
        "password": "local-only-admin-password",
    },
    {
        "role": "member",
        "user_id": "22222222-2222-4222-8222-222222222222",
        "identity_id": "77777777-7777-4777-8777-777777777777",
        "subject": "33333333-3333-4333-8333-333333333333",
        "email": "dev.member@example.com",
        "password": "local-only-member-password",
    },
)

# The stack's email-hmac keyring (compose.yaml, EMAIL_HMAC_KEYRING): a suppression is stored by
# the address's pseudonym under it, never the address (sft.core.pseudonyms).
EMAIL_KEY_ID = "local"
EMAIL_KEY = base64.b64decode("eXl5eXl5eXl5eXl5eXl5eXl5eXl5eXl5eXl5eXl5eXk=")


class NotLocalError(SystemExit):
    pass


def pseudonym(address: str) -> str:
    normalized = address.strip().lower()
    digest = hmac.new(
        EMAIL_KEY, b"email/v1/" + normalized.encode(), hashlib.sha256
    ).digest()
    return (
        f"e{EMAIL_KEY_ID}:"
        + base64.urlsafe_b64encode(digest[:16]).rstrip(b"=").decode()
    )


def check_local(url: str, connection: psycopg.Connection) -> None:
    """Refuse anything but the local stack's database."""
    parts = urlsplit(url)
    if parts.hostname not in LOOPBACK or parts.path.lstrip("/") != "sft":
        raise NotLocalError(
            "refused: the seed runs only against the local stack's database"
        )
    found = connection.execute(
        "SELECT (SELECT count(*) FROM pg_roles WHERE rolname IN ('sft_api', 'sft_jobs', "
        "'sft_owner')), to_regclass('public.user_identities') IS NOT NULL"
    ).fetchone()
    if found is None or found[0] != 3 or not found[1]:
        raise NotLocalError(
            "refused: this database isn't the local stack's (run `make up` first)"
        )


def seed(connection: psycopg.Connection, suppress: list[str]) -> dict[str, int]:
    """Write every row once; how many each statement added."""
    added: dict[str, int] = {}

    def run(name: str, sql: str, params: dict[str, object]) -> None:
        cursor = connection.execute(sql, params)
        added[name] = added.get(name, 0) + cursor.rowcount

    run(
        "idp_connections",
        "INSERT INTO idp_connections (id, tenant_id, kind, provider_name, issuer, status) "
        "VALUES (%(id)s, NULL, 'local', %(provider)s, %(issuer)s, 'active') "
        "ON CONFLICT DO NOTHING",
        {"id": CONNECTION_ID, "provider": PROVIDER, "issuer": ISSUER},
    )
    [(connection_id,)] = connection.execute(
        "SELECT id FROM idp_connections WHERE provider_name = %(provider)s",
        {"provider": PROVIDER},
    ).fetchall()
    run(
        "tenants",
        "INSERT INTO tenants (id, name, status, recovery_contact) "
        "VALUES (%(id)s, %(name)s, 'active', 'dev.admin@example.com') ON CONFLICT DO NOTHING",
        {"id": TENANT_ID, "name": TENANT_NAME},
    )
    run(
        "tenant_policies",
        "INSERT INTO tenant_policies (tenant_id, default_locale) VALUES (%(id)s, 'en') "
        "ON CONFLICT DO NOTHING",
        {"id": TENANT_ID},
    )
    for user in USERS:
        run(
            "users",
            "INSERT INTO users (id, tenant_id, email, email_normalized, role, status) "
            "VALUES (%(user_id)s, %(tenant)s, %(email)s, lower(%(email)s), %(role)s, 'active') "
            "ON CONFLICT DO NOTHING",
            {**user, "tenant": TENANT_ID},
        )
        run(
            "user_identities",
            "INSERT INTO user_identities (id, tenant_id, user_id, idp_connection_id, subject) "
            "VALUES (%(identity_id)s, %(tenant)s, %(user_id)s, %(connection)s, %(subject)s) "
            "ON CONFLICT DO NOTHING",
            {**user, "tenant": TENANT_ID, "connection": connection_id},
        )
    for address in suppress:
        run(
            "email_suppressions",
            "INSERT INTO email_suppressions (id, tenant_id, email_hmac, hmac_key_id, reason) "
            "VALUES (gen_random_uuid(), %(tenant)s, %(hmac)s, %(key)s, 'complaint') "
            "ON CONFLICT DO NOTHING",
            {"tenant": TENANT_ID, "hmac": pseudonym(address), "key": EMAIL_KEY_ID},
        )
    return added


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Seed the local stack (docs/local-development.md)"
    )
    parser.add_argument(
        "--suppress",
        action="append",
        default=[],
        metavar="ADDRESS",
        help="also suppress this address in the tenant, as a complaint would (repeatable)",
    )
    parser.add_argument(
        "--json", action="store_true", help="print the sign-in details as JSON"
    )
    args = parser.parse_args()
    url = os.environ.get("LOCAL_POSTGRES_URL", DEFAULT_URL)
    try:
        with psycopg.connect(url, connect_timeout=5) as connection:
            check_local(url, connection)
            added = seed(connection, args.suppress)
    except NotLocalError as refused:
        print(refused, file=sys.stderr)
        return 2
    except psycopg.OperationalError as exc:
        print(f"the local database isn't reachable ({type(exc).__name__}): run `make up` first",
              file=sys.stderr)  # fmt: skip
        return 1
    details = {
        "web_app": WEB_APP,
        "sign_in": "http://localhost:8000/v1/auth/sign-in",
        "keycloak": ISSUER,
        "tenant": {"id": TENANT_ID, "name": TENANT_NAME},
        "users": [
            {k: u[k] for k in ("role", "email", "password", "user_id")} for u in USERS
        ],
        "added": added,
    }
    if args.json:
        print(json.dumps(details, indent=2))
        return 0
    print(f"Seeded the local stack (rows added this run: {sum(added.values())}).")
    print(f"Tenant: {TENANT_NAME} ({TENANT_ID})")
    print(
        f"Sign in at {WEB_APP}, or start at {details['sign_in']}, through Keycloak ({ISSUER}):"
    )
    for user in USERS:
        print(f"  {user['role']:6}  {user['email']}  password: {user['password']}")
    print("Every credential here is local-only and fake.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
