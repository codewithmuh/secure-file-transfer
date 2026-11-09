"""The load test's tenants and API keys on the local stack (#249): what an operator
provisions in staging.

    uv run --project services/api python loadtest/setup_local.py \\
        --tenants 2 --keys-per-tenant 2 --out KEYS.json

Each load-test tenant gets one admin, its DLP policy in monitor mode (an API key can't
confirm a DLP warning, so a warning would stop every send) and `--keys-per-tenant` API
keys with the four transfer and upload-request scopes, made at run time, valid for a
day. Earlier load-test keys are revoked first. The keys go to `--out` only (mode 0600,
JSON `[{"tenant": ..., "key": ...}]`), never to the terminal.

Like local/seed.py, it writes as the local server's superuser and refuses any database
but the local stack's: the URL must name the loopback address and the `sft` database.
Why 2 tenants and 2 keys at the local profile's 5 % of the peak hour: group H allows 300
calls a minute per key and 1,000 per tenant (abuse 2.2), and the run needs about 450.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import urlsplit

import psycopg
from sft.service.api_keys import key_hash, key_prefix, new_key

DEFAULT_URL = "postgresql://sft:sft-local-only@127.0.0.1:5432/sft"
LOOPBACK = frozenset({"127.0.0.1", "localhost", "::1"})
NAMESPACE = uuid.UUID("10ad7e57-0000-4000-8000-000000000000")
SCOPES = [
    "transfers:read",
    "transfers:write",
    "upload_requests:read",
    "upload_requests:write",
]


def provision(
    db: psycopg.Connection, tenants: int, per_tenant: int
) -> list[dict[str, str]]:
    keys = []
    expires = datetime.now(UTC) + timedelta(days=1)
    for n in range(tenants):
        tenant = str(uuid.uuid5(NAMESPACE, f"tenant-{n}"))
        admin = str(uuid.uuid5(NAMESPACE, f"admin-{n}"))
        email = f"loadtest-admin-{n}@example.com"
        db.execute(
            "INSERT INTO tenants (id, name, status, recovery_contact) VALUES "
            "(%(t)s, %(name)s, 'active', 'loadtest-owner@example.com') ON CONFLICT DO NOTHING",
            {"t": tenant, "name": f"Load test {n}"},
        )
        db.execute(
            "INSERT INTO tenant_policies (tenant_id, default_locale) VALUES (%(t)s, 'en') "
            "ON CONFLICT DO NOTHING",
            {"t": tenant},
        )
        db.execute(
            "INSERT INTO users (id, tenant_id, email, email_normalized, role, status) VALUES "
            "(%(u)s, %(t)s, %(e)s, %(e)s, 'admin', 'active') ON CONFLICT DO NOTHING",
            {"u": admin, "t": tenant, "e": email},
        )
        db.execute(
            "SELECT dlp_default_policy(%(t)s, %(u)s, 'en') "
            "WHERE NOT EXISTS (SELECT FROM dlp_policies WHERE tenant_id = %(t)s)",
            {"t": tenant, "u": admin},
        )
        db.execute(
            "UPDATE dlp_policies SET mode = 'monitor' WHERE tenant_id = %(t)s",
            {"t": tenant},
        )
        db.execute(
            "UPDATE api_keys SET revoked_at = now(), revoked_reason = 'admin' "
            "WHERE tenant_id = %(t)s AND revoked_at IS NULL",
            {"t": tenant},
        )
        for _ in range(per_tenant):
            key = new_key("dev")  # the local stack's API_KEY_ENVIRONMENT
            db.execute(
                "INSERT INTO api_keys (id, tenant_id, created_by, name, key_prefix, key_hash, "
                "scopes, expires_at) VALUES (gen_random_uuid(), %(t)s, %(u)s, 'load test', "
                "%(prefix)s, %(hash)s, %(scopes)s, %(expires)s)",
                {
                    "t": tenant,
                    "u": admin,
                    "prefix": key_prefix(key),
                    "hash": key_hash(key),
                    "scopes": SCOPES,
                    "expires": expires,
                },
            )
            keys.append({"tenant": tenant, "key": key})
    return keys


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Provision the load test on the local stack"
    )
    parser.add_argument("--tenants", type=int, default=2)
    parser.add_argument("--keys-per-tenant", type=int, default=2)
    parser.add_argument(
        "--out", type=Path, required=True, help="where the keys go (mode 0600)"
    )
    args = parser.parse_args()
    url = os.environ.get("LOCAL_POSTGRES_URL", DEFAULT_URL)
    parts = urlsplit(url)
    if parts.hostname not in LOOPBACK or parts.path.lstrip("/") != "sft":
        print(
            "refused: this runs only against the local stack's database",
            file=sys.stderr,
        )
        return 2
    with psycopg.connect(url, connect_timeout=5) as db:
        keys = provision(db, args.tenants, args.keys_per_tenant)
    descriptor = os.open(args.out, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "w") as out:
        json.dump(keys, out)
    print(f"{len(keys)} keys for {args.tenants} tenants written to {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
