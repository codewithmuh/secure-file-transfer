"""The synthetic probe against the local stack (#248's acceptance): the real `Probe`, through the
public API, the S3 stand-in and Mailpit, after `make up` and `make seed`.

It gives the stack what an operator gives each environment (docs/runbooks/synthetic-probe.md,
"Setting up the synthetic tenant"): a tenant of its own with one admin, its DLP policy in monitor
mode, and an API key with `transfers:read` and `transfers:write`. Locally that is written straight
into the database as its superuser, as the seed does, and the key is made at run time, so nothing
key-shaped is in the repository. Every earlier probe key is revoked first.

Skipped unless SFT_E2E=1, like the M2 journey. The E2E_* variables point it at a stack on other
ports (docs/operations/performance.md).
"""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta

import psycopg
import pytest

from sft.probe.journey import Probe
from sft.probe.mailbox import MailpitMailbox
from sft.probe.settings import ProbeSettings
from sft.service.api_keys import key_hash, key_prefix, new_key

pytestmark = [
    pytest.mark.e2e,
    pytest.mark.skipif(os.environ.get("SFT_E2E") != "1", reason="runs against the local stack"),
]

ENV = {
    "API_URL": "http://localhost:8000",
    "WEB_ORIGIN": "http://localhost:3000",
    "MAILPIT_URL": "http://127.0.0.1:8025",
    # Part URLs name the S3 stand-in as a browser on the host reaches it; set this when the stack
    # publishes it elsewhere.
    "S3_PART_HOST": "",
    "LOCAL_POSTGRES_URL": "postgresql://sft:sft-local-only@127.0.0.1:5432/sft",
}
cfg = {name: os.environ.get(f"E2E_{name}", default) for name, default in ENV.items()}

TENANT_ID = "5eed0000-0000-4000-8000-0000000000b1"
ADMIN_ID = "5eed0000-0000-4000-8000-0000000000b2"
MAILBOX_DOMAIN = "probe.sft.localhost"


def provision_probe_tenant() -> str:
    """The synthetic tenant, its admin, monitor mode and a fresh key; the key, never printed."""
    key = new_key("dev")  # the stack's API_KEY_ENVIRONMENT
    now = datetime.now(UTC)
    with psycopg.connect(cfg["LOCAL_POSTGRES_URL"]) as db:
        db.execute(
            "INSERT INTO tenants (id, name, status, recovery_contact) VALUES "
            "(%(t)s, 'Synthetic probe', 'active', 'probe-owner@example.com') "
            "ON CONFLICT DO NOTHING",
            {"t": TENANT_ID},
        )
        db.execute(
            "INSERT INTO tenant_policies (tenant_id, default_locale) VALUES (%(t)s, 'en') "
            "ON CONFLICT DO NOTHING",
            {"t": TENANT_ID},
        )
        db.execute(
            "INSERT INTO users (id, tenant_id, email, email_normalized, role, status) VALUES "
            "(%(u)s, %(t)s, 'probe-admin@example.com', 'probe-admin@example.com', 'admin', "
            "'active') ON CONFLICT DO NOTHING",
            {"u": ADMIN_ID, "t": TENANT_ID},
        )
        db.execute(
            "SELECT dlp_default_policy(%(t)s, %(u)s, 'en') "
            "WHERE NOT EXISTS (SELECT FROM dlp_policies WHERE tenant_id = %(t)s)",
            {"t": TENANT_ID, "u": ADMIN_ID},
        )
        # An API key can't confirm a DLP warning (confirmTransfer), and the default policy warns
        # on a recipient domain new to the tenant: the synthetic tenant runs in monitor mode.
        db.execute(
            "UPDATE dlp_policies SET mode = 'monitor' WHERE tenant_id = %(t)s", {"t": TENANT_ID}
        )
        db.execute(
            "UPDATE api_keys SET revoked_at = now(), revoked_reason = 'admin' "
            "WHERE tenant_id = %(t)s AND revoked_at IS NULL",
            {"t": TENANT_ID},
        )
        db.execute(
            "INSERT INTO api_keys (id, tenant_id, created_by, name, key_prefix, key_hash, scopes, "
            "expires_at) VALUES (gen_random_uuid(), %(t)s, %(u)s, 'synthetic probe', %(prefix)s, "
            "%(hash)s, ARRAY['transfers:read', 'transfers:write'], %(expires)s)",
            {
                "t": TENANT_ID,
                "u": ADMIN_ID,
                "prefix": key_prefix(key),
                "hash": key_hash(key),
                "expires": now + timedelta(days=1),
            },
        )
    return key


def probe_settings(key: str) -> ProbeSettings:
    return ProbeSettings(
        environment="local",
        probe_api_url=cfg["API_URL"],
        probe_web_origin=cfg["WEB_ORIGIN"],
        probe_api_key=key,
        probe_mailbox="mailpit",
        probe_mailpit_url=cfg["MAILPIT_URL"],
        probe_mailbox_domain=MAILBOX_DOMAIN,
        probe_part_url_host=cfg["S3_PART_HOST"] or None,
        probe_timeout_seconds=240,
    )


def test_the_probe_passes_against_the_local_stack() -> None:
    settings = probe_settings(provision_probe_tenant())
    probe = Probe(settings, MailpitMailbox(cfg["MAILPIT_URL"]))
    try:
        result = probe.run()
    finally:
        probe.close()
    assert result.passed, (result.failed_step, result.reason)
    assert result.first_byte_seconds is not None
    assert result.first_byte_seconds < 1.0  # NFR-4, on a laptop
    # The transfer was revoked: its link is gone for good.
    with psycopg.connect(cfg["LOCAL_POSTGRES_URL"]) as db:
        states = db.execute(
            "SELECT state FROM transfers WHERE tenant_id = %(t)s ORDER BY created_at DESC LIMIT 1",
            {"t": TENANT_ID},
        ).fetchall()
    assert states == [("revoked",)]


def test_a_refused_key_fails_the_create_step_by_name() -> None:
    settings = probe_settings(new_key("dev"))  # well formed, never stored
    probe = Probe(settings, MailpitMailbox(cfg["MAILPIT_URL"]))
    try:
        result = probe.run()
    finally:
        probe.close()
    assert (result.failed_step, result.reason) == (
        "create",
        "createTransfer answered 401 credentials_invalid",
    )
