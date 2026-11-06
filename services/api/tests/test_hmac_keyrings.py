"""The link-hmac and code-hmac keyrings (#178, #179; data model 2.2, 2.4; encryption and keys
6.2)."""

import base64
import hashlib
import hmac
import uuid
from datetime import UTC, datetime, timedelta, timezone

import pytest

from sft.core.hmac_keyrings import (
    CodeKeyring,
    KeyringError,
    LinkKeyring,
    UnknownKeyError,
    epoch_micros,
)

OLD = base64.b64encode(b"o" * 32).decode()
NEW = base64.b64encode(b"n" * 32).decode()
RING = (
    f'[{{"id":"k2","state":"active","key":"{NEW}"}},{{"id":"k1","state":"verify","key":"{OLD}"}}]'
)
SUBJECT = uuid.UUID("01970000-0000-7000-8000-000000000001")
ISSUED = datetime(2026, 11, 6, 1, 2, 3, 456789, tzinfo=UTC)


def test_a_link_token_is_the_documented_hmac() -> None:
    keys = LinkKeyring.from_json(RING)
    assert keys.active_id == "k2"
    micros = epoch_micros(ISSUED)
    assert micros == 1_793_926_923_456_789
    expected = hmac.new(b"n" * 32, f"link/v1/{SUBJECT}/{micros}".encode(), hashlib.sha256)
    token = keys.token("k2", SUBJECT, ISSUED)
    assert token == base64.urlsafe_b64encode(expected.digest()).rstrip(b"=").decode()
    assert len(token) == 43  # 256 bits, more than NFR-14's 128


def test_the_same_row_rebuilds_the_same_token_under_any_loaded_key() -> None:
    keys = LinkKeyring.from_json(RING)
    assert keys.token("k1", SUBJECT, ISSUED) == keys.token("k1", SUBJECT, ISSUED)
    assert keys.token("k1", SUBJECT, ISSUED) != keys.token("k2", SUBJECT, ISSUED)
    # The same instant in another zone is the same link; a microsecond later is a new one.
    tokyo = ISSUED.astimezone(timezone(timedelta(hours=9)))
    assert keys.token("k2", SUBJECT, tokyo) == keys.token("k2", SUBJECT, ISSUED)
    later = ISSUED + timedelta(microseconds=1)
    assert keys.token("k2", SUBJECT, later) != keys.token("k2", SUBJECT, ISSUED)
    assert keys.knows("k1")
    assert not keys.knows("k0")
    with pytest.raises(UnknownKeyError):
        keys.token("k0", SUBJECT, ISSUED)


def test_a_naive_issue_time_is_refused() -> None:
    with pytest.raises(ValueError, match="aware"):
        epoch_micros(datetime(2026, 1, 1))


def test_a_code_matches_only_its_own_row_and_key() -> None:
    keys = CodeKeyring.from_json(RING)
    code_id, other = uuid.uuid4(), uuid.uuid4()
    stored = keys.code_hmac("k2", code_id, "123456")
    assert keys.matches("k2", code_id, "123456", stored)
    assert not keys.matches("k2", code_id, "123457", stored)
    assert not keys.matches("k2", other, "123456", stored)
    assert not keys.matches("k1", code_id, "123456", stored)
    assert not keys.matches("gone", code_id, "123456", stored)  # a retired key: unusable


@pytest.mark.parametrize("cls", [LinkKeyring, CodeKeyring])
def test_a_bad_keyring_is_refused_without_its_key(cls: type[LinkKeyring | CodeKeyring]) -> None:
    with pytest.raises(KeyringError) as refused:
        cls.from_json(f'[{{"id":"a_b","state":"active","key":"{NEW}"}}]')
    assert NEW not in str(refused.value)
    assert NEW not in repr(cls.from_json(RING))
