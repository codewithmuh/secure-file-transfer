import base64
import hashlib
import hmac
import json
from datetime import UTC, datetime, timedelta

import pytest

from sft.core.keyrings import KeyringError
from sft.core.pseudonyms import (
    LIMIT_OVERLAP,
    EmailKey,
    EmailKeyring,
    EmailPseudonyms,
    email_pseudonym,
)

KEY = b"k" * 32  # test-only
ACTIVATED = datetime(2026, 11, 1, tzinfo=UTC)


def test_the_pseudonym_is_the_documented_hmac() -> None:
    # encryption and keys 6.2: "e" + key ID + ":" + base64url(HMAC-SHA-256), truncated to 128 bits.
    digest = hmac.new(KEY, b"email/v1/dev.member@example.com", hashlib.sha256).digest()[:16]
    expected = "e2026:" + base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
    assert email_pseudonym("2026", KEY, "dev.member@example.com") == expected
    assert len(expected.split(":")[1]) == 22
    assert "example" not in expected


@pytest.mark.parametrize("key_id", ["", "a:b", "x" * 33, "{tag}"])
def test_key_ids_are_plain(key_id: str) -> None:
    with pytest.raises(ValueError, match="key ID"):
        email_pseudonym(key_id, KEY, "a@example.com")


def test_within_scopes_every_pseudonym() -> None:
    scoped = EmailPseudonyms("e2:new", ("e1:old",)).within("tenant")
    assert scoped == EmailPseudonyms("tenant:e2:new", ("tenant:e1:old",))


def keyring() -> EmailKeyring:
    return EmailKeyring(
        [
            EmailKey("old", b"o" * 32, "verify"),
            EmailKey("new", KEY, "active", activated_at=ACTIVATED),
            EmailKey("next", b"n" * 32, "staged"),
        ]
    )


def test_limits_add_the_previous_key_for_25_hours() -> None:
    during = keyring().for_limits("a@example.com", ACTIVATED + LIMIT_OVERLAP - timedelta(seconds=1))
    assert during.active == email_pseudonym("new", KEY, "a@example.com")
    assert during.overlap == (email_pseudonym("old", b"o" * 32, "a@example.com"),)
    after = keyring().for_limits("a@example.com", ACTIVATED + LIMIT_OVERLAP)
    assert after.overlap == ()


def test_a_keyring_needs_one_active_key_with_its_time() -> None:
    with pytest.raises(ValueError, match="exactly one active"):
        EmailKeyring([EmailKey("a", KEY, "active")])
    with pytest.raises(ValueError, match="exactly one active"):
        EmailKeyring([EmailKey("a", KEY, "verify")])
    assert "kkkk" not in repr(EmailKey("a", KEY, "active"))


def test_the_keyring_is_read_from_its_secret() -> None:
    # The secret's shape (encryption and keys 6.5): the old key verifies for the 25-hour overlap.
    encoded = base64.b64encode(KEY).decode()
    newer = base64.b64encode(b"n" * 32).decode()
    raw = json.dumps(
        [
            {"id": "2025", "state": "verify", "key": encoded},
            {"id": "2026", "state": "active", "key": newer, "activated_at": ACTIVATED.isoformat()},
            {"id": "2027", "state": "staged", "key": base64.b64encode(b"s" * 32).decode()},
        ]
    )
    keyring = EmailKeyring.from_json(raw)
    during = keyring.for_limits("a@example.com", ACTIVATED + timedelta(hours=1))
    assert during.active == email_pseudonym("2026", b"n" * 32, "a@example.com")
    assert during.overlap == (email_pseudonym("2025", KEY, "a@example.com"),)
    assert keyring.for_limits("a@example.com", ACTIVATED + LIMIT_OVERLAP).overlap == ()


@pytest.mark.parametrize(
    "entry",
    [
        {"id": "a", "state": "active"},  # no activated_at
        {"id": "a_b", "state": "active", "activated_at": "2026-11-01T00:00:00+00:00"},
        {"id": "a", "state": "verify", "activated_at": "2026-11-01T00:00:00+00:00"},  # none active
        {"id": "a", "state": "active", "activated_at": "yesterday"},
    ],
)
def test_a_bad_keyring_is_refused_without_its_key(entry: dict[str, str]) -> None:
    encoded = base64.b64encode(KEY).decode()
    with pytest.raises(KeyringError) as caught:
        EmailKeyring.from_json(json.dumps([{**entry, "key": encoded}]))
    assert encoded not in str(caught.value)
