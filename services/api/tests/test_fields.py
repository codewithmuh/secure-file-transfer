"""Field encryption without a database (#236, #233): the stored format, the binding of each value
to its tenant, table, column, row and key version, the KMS stand-in's context rules, the key cache,
the AWS adapter's calls, and the DLP finding details' stored form and location hints."""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from botocore.stub import Stubber
from prometheus_client import CollectorRegistry
from pydantic import ValidationError

from api_settings import API_SETTINGS
from sft.core import sealed
from sft.core.sealed import Column, SealedAuthenticationError, SealedValueError
from sft.core.settings import FieldKeySettings, ScanSettings, Settings
from sft.runtime.kms import AwsKms, LocalKms, open_kms
from sft.service import fields
from sft.service.fields import (
    FieldDecryptError,
    FieldKeys,
    FieldKeysUnavailableError,
    FieldMetrics,
    KeyPurpose,
    KeyServiceError,
    TenantKeys,
)
from sft.service.finding_details import Location, decode, encode, parse_location

pytestmark = pytest.mark.anyio

TENANT, OTHER = uuid.uuid4(), uuid.uuid4()
ROW = uuid.uuid4()
KEY = bytes(range(32))


def keys_of(tenant: uuid.UUID, purpose: KeyPurpose = KeyPurpose.FIELD) -> TenantKeys:
    metrics = FieldMetrics.create(CollectorRegistry())
    return TenantKeys(tenant, purpose, 1, {1: KEY}, metrics)


# ---- the format (sft.core.sealed) ----


def test_a_sealed_value_is_format_1_names_its_version_and_holds_no_text() -> None:
    value = keys_of(TENANT).seal(fields.FILE_NAME, ROW, "Q3 layoffs.xlsx")
    assert value[0] == sealed.AEAD_FORMAT
    assert sealed.key_version(value) == 1
    assert b"layoffs" not in value
    assert keys_of(TENANT).open(fields.FILE_NAME, ROW, value) == "Q3 layoffs.xlsx"


def test_two_seals_of_one_text_differ() -> None:
    keys = keys_of(TENANT)
    assert keys.seal(fields.FILE_NAME, ROW, "a") != keys.seal(fields.FILE_NAME, ROW, "a")


@pytest.mark.parametrize(
    ("tenant", "column", "row"),
    [
        (OTHER, fields.FILE_NAME, ROW),  # another tenant: the third isolation layer
        (TENANT, fields.TRANSFER_MESSAGE, ROW),  # moved to another column
        (TENANT, fields.FILE_NAME, uuid.uuid4()),  # moved to another row
    ],
)
def test_a_value_opens_only_where_it_was_sealed(
    tenant: uuid.UUID, column: Column, row: uuid.UUID
) -> None:
    value = keys_of(TENANT).seal(fields.FILE_NAME, ROW, "secret plans")
    other = keys_of(tenant)
    with pytest.raises(FieldDecryptError) as refused:
        other.open(column, row, value)
    assert "secret" not in str(refused.value)
    assert other._metrics.scope_mismatches.labels("field-dek")._value.get() == 1


def test_a_version_the_tenant_lacks_counts_as_a_mismatch() -> None:
    value = keys_of(TENANT).seal(fields.FILE_NAME, ROW, "x")
    lacking = TenantKeys(
        TENANT, KeyPurpose.FIELD, 2, {2: KEY}, FieldMetrics.create(CollectorRegistry())
    )
    with pytest.raises(FieldDecryptError):
        lacking.open(fields.FILE_NAME, ROW, value)


def test_a_tampered_value_fails_authentication() -> None:
    value = bytearray(keys_of(TENANT).seal(fields.FILE_NAME, ROW, "x"))
    value[-1] ^= 1
    with pytest.raises(SealedAuthenticationError):
        sealed.decrypt(
            KEY,
            purpose="field-dek",
            tenant_id=TENANT,
            column=fields.FILE_NAME,
            row_id=ROW,
            value=bytes(value),
        )


def test_format_0_is_read_and_counted_but_never_written() -> None:
    keys = keys_of(TENANT)
    assert keys.open(fields.FILE_NAME, ROW, b"\x00hello") == "hello"
    assert keys._metrics.plaintext_reads.labels("files.display_name_ct")._value.get() == 1
    assert sealed.key_version(b"\x00hello") is None
    with pytest.raises(SealedValueError):
        keys.open(fields.FILE_NAME, ROW, b"\x07junk")


def test_a_column_opens_only_with_its_purpose_key() -> None:
    with pytest.raises(ValueError, match="isn't sealed with"):
        keys_of(TENANT).seal(fields.FINDING_DETAIL, ROW, "x")
    with pytest.raises(ValueError, match="isn't sealed with"):
        keys_of(TENANT, KeyPurpose.DLP).seal(fields.FILE_NAME, ROW, "x")


def test_without_a_live_key_nothing_is_sealed() -> None:
    keys = TenantKeys(TENANT, KeyPurpose.FIELD, None, {}, FieldMetrics.create(CollectorRegistry()))
    with pytest.raises(FieldKeysUnavailableError):
        keys.seal(fields.FILE_NAME, ROW, "x")


def test_a_process_without_keys_opens_nothing() -> None:
    previous = fields.install(None)
    try:
        with pytest.raises(FieldKeysUnavailableError):
            fields.installed()
    finally:
        fields.install(previous)


# ---- the KMS stand-in, and the key policy it mimics ----


async def test_the_stand_in_binds_the_context() -> None:
    kms = LocalKms()
    context = fields.context(KeyPurpose.FIELD, TENANT)
    key, wrapped = await kms.generate_data_key(context)
    assert await kms.decrypt(wrapped, context) == key
    assert key not in wrapped
    for wrong in (fields.context(KeyPurpose.FIELD, OTHER), fields.context(KeyPurpose.DLP, TENANT)):
        with pytest.raises(KeyServiceError, match="InvalidCiphertextException"):
            await kms.decrypt(wrapped, wrong)
    rewrapped = await kms.re_encrypt(wrapped, context)
    assert rewrapped != wrapped
    assert await kms.decrypt(rewrapped, context) == key


async def test_the_scan_workers_stand_in_refuses_a_field_data_key() -> None:
    # As the fields key's policy: the scan worker may use dlp-dek only (encryption and keys 4.4).
    kms = LocalKms(purposes=frozenset({"dlp-dek"}))
    with pytest.raises(KeyServiceError, match="AccessDenied"):
        await kms.generate_data_key(fields.context(KeyPurpose.FIELD, TENANT))
    await kms.generate_data_key(fields.context(KeyPurpose.DLP, TENANT))
    with pytest.raises(KeyServiceError, match="AccessDenied"):
        await kms.generate_data_key({"purpose": "dlp-dek"})  # no tenant in the context


async def test_a_workload_never_asks_for_a_purpose_its_role_lacks() -> None:
    keys = FieldKeys(
        LocalKms(), FieldMetrics.create(CollectorRegistry()), purposes=frozenset({KeyPurpose.DLP})
    )
    with pytest.raises(FieldKeysUnavailableError):
        await keys.tenant(None, TENANT, KeyPurpose.FIELD)  # type: ignore[arg-type]


async def test_unwrapped_keys_are_cached_at_most_15_minutes() -> None:
    now = [0.0]
    kms = LocalKms()
    calls = []

    async def counted(wrapped: bytes, context: Any) -> bytes:
        calls.append(1)
        return LocalKms._unwrap(kms, wrapped, context)

    kms.decrypt = counted  # type: ignore[method-assign]
    keys = FieldKeys(
        kms, FieldMetrics.create(CollectorRegistry()), cache_seconds=3600, clock=lambda: now[0]
    )
    key, wrapped = await kms.generate_data_key(fields.context(KeyPurpose.FIELD, TENANT))
    from sft.data.data_keys import WrappedKey

    row = WrappedKey(1, wrapped, None, None)  # type: ignore[arg-type]
    assert await keys.unwrap(TENANT, KeyPurpose.FIELD, row) == key
    now[0] = 899.0
    await keys.unwrap(TENANT, KeyPurpose.FIELD, row)
    assert len(calls) == 1
    now[0] = 901.0  # the 1 hour asked for is cut to 15 minutes
    await keys.unwrap(TENANT, KeyPurpose.FIELD, row)
    assert len(calls) == 2
    keys.forget()
    await keys.unwrap(TENANT, KeyPurpose.FIELD, row)
    assert len(calls) == 3


# ---- the AWS adapter ----


async def test_aws_kms_names_the_key_and_the_context_on_every_call() -> None:
    kms = AwsKms.create(region="ap-northeast-1", key_id="alias/sft/dev/fields", threads=1)
    client = kms._client
    context = fields.context(KeyPurpose.DLP, TENANT)
    blob, key = b"w" * 40, b"k" * 32
    with Stubber(client) as stub:  # type: ignore[arg-type]
        stub.add_response(
            "generate_data_key",
            {"CiphertextBlob": blob, "Plaintext": key, "KeyId": "k"},
            {"KeyId": "alias/sft/dev/fields", "KeySpec": "AES_256", "EncryptionContext": context},
        )
        stub.add_response(
            "decrypt",
            {"Plaintext": key, "KeyId": "k"},
            {"KeyId": "alias/sft/dev/fields", "CiphertextBlob": blob, "EncryptionContext": context},
        )
        stub.add_response(
            "re_encrypt",
            {"CiphertextBlob": b"v" * 40, "KeyId": "k"},
            {
                "CiphertextBlob": blob,
                "SourceKeyId": "alias/sft/dev/fields",
                "SourceEncryptionContext": context,
                "DestinationKeyId": "alias/sft/dev/fields",
                "DestinationEncryptionContext": context,
            },
        )
        stub.add_client_error("decrypt", "AccessDeniedException")
        assert await kms.generate_data_key(context) == (key, blob)
        assert await kms.decrypt(blob, context) == key
        assert await kms.re_encrypt(blob, context) == b"v" * 40
        with pytest.raises(KeyServiceError, match="AccessDeniedException"):
            await kms.decrypt(blob, context)
    await kms.close()


def test_the_settings_choose_kms_or_the_stand_in() -> None:
    assert isinstance(open_kms(key_id="local", region="ap-northeast-1"), LocalKms)
    assert isinstance(open_kms(key_id="alias/sft/dev/fields", region="ap-northeast-1"), AwsKms)
    base: dict[str, Any] = {**API_SETTINGS, "database_url": "postgresql://sft_api@db/sft"}
    for good in (
        "local",
        "alias/sft/prod/fields",
        "arn:aws:kms:ap-northeast-1:000000000000:key/mrk-" + "0" * 32,
    ):
        Settings(**{**base, "fields_kms_key_id": good})
    for bad in ("", "fields", "arn:aws:kms:x"):
        with pytest.raises(ValidationError):
            Settings(**{**base, "fields_kms_key_id": bad})
    scan: dict[str, Any] = {
        "database_url": "postgresql://sft_scan@db/sft",
        "sqs_queue_prefix": "sft-dev-",
        "scan_pool": "small",
        "s3_files_bucket": "sft-test-files",
        "s3_large_files_bucket": "sft-test-large-files",
    }
    with pytest.raises(ValidationError, match="fields_kms_key_id"):
        ScanSettings(**scan)
    ScanSettings(**scan, fields_kms_key_id="alias/sft/dev/fields")
    FieldKeySettings(database_url="postgresql://sft_api@db/sft", fields_kms_key_id="local")  # type: ignore[arg-type]


# ---- DLP finding details (#233) ----


def test_details_keep_at_most_10_hints_and_3_previews() -> None:
    text = encode([f"page {n}" for n in range(1, 13)], ["a", "b", "c", "d" * 100])
    details = decode(text)
    assert [loc.page for loc in details.locations] == list(range(1, 11))
    assert details.previews == ("a", "b", "c")


@pytest.mark.parametrize(
    ("hint", "location"),
    [
        ("page 12", Location(page=12)),
        ('sheet "顧客一覧", row 340', Location(sheet="顧客一覧", row=340)),
        ("slide 4", Location(slide=4)),
        ("slide 4, notes", Location(slide=4, part="notes")),
        ("line 88", Location(line=88)),
        ("paragraph 3", Location(paragraph=3)),
        ("header", Location(part="header")),
        ("endnotes", Location(part="footnotes")),
        ("document properties", Location(part="properties")),
        ("message", Location(part="message")),
        (
            'contracts/2026/appendix.xlsx, sheet "2", row 9',
            Location(member="contracts/2026/appendix.xlsx", sheet="2", row=9),
        ),
        ("a.zip, b.docx, paragraph 1", Location(member="a.zip, b.docx", paragraph=1)),
        ("chart", Location(member="chart", part="body")),
        ("file", Location(part="body")),
        ("page 0", Location(member="page 0", part="body")),
    ],
)
def test_location_hints_read_into_the_contracts_shape(hint: str, location: Location) -> None:
    assert parse_location(hint) == location
