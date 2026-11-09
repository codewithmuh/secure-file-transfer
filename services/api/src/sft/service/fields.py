"""Field encryption: sealing file names, messages and other free text for their `*_ct` columns
(#236; encryption and keys 3.2, 3.3, 7.2; ADR-0017), and the DLP values of #233 the same way.

**Envelope encryption.** Each tenant has a data key per purpose: `field-dek` for file names,
transfer and upload request messages, justifications and approvers' comments; `dlp-dek` for DLP
finding details and detector definitions. KMS generates each one under the fields key with the
encryption context `{"purpose": ..., "tenant_id": ...}`; only the wrapped key is stored
(`sft.data.data_keys`). An unwrapped key stays in this process's memory for at most 15 minutes,
never on disk, in a log, a trace or a message.

**Values** are AES-256-GCM in format 1 (`sft.core.sealed`), bound to the purpose, the tenant, the
table, the column, the row's ID and the key version. A write is read back and checked before it
is returned. Format 0, M2's unencrypted stand-in, is still read, and counted, until the field key
job's backfill has resealed every row (`sft.service.field_keys`); it is never written.

**The caller's tenant.** `tenant_keys(session, tenant_id)` loads the keys of the tenant in the
session's scope: the caller's (a member, an API key, a link session, or for a worker the message's
tenant), never the tenant on a row. A row of another tenant fails authentication instead of
decrypting: `FieldDecryptError`, counted as `field_decrypt_scope_mismatch_total`, which pages as a
possible isolation breach (the third isolation layer, data model 4.2).

**Who may unwrap what.** Each process installs one `FieldKeys` at startup with the purposes its
role may use, as the fields key's policy says (4.3, 4.4): the API both, the scan worker `dlp-dek`
only, the field key job (the API's role) both. A process that installed none, such as the
notification worker or the operator API, can't seal or open anything. Keys come from KMS through
`KeyService`: `sft.runtime.kms.AwsKms` in AWS, and the in-process stand-in
`sft.runtime.kms.LocalKms` in the local stack and the tests, which enforces the same encryption
context rules.

Nothing here logs, traces or raises a value or a key: messages and log lines name the tenant, the
column and the row, by ID.
"""

from __future__ import annotations

import hashlib
import logging
import time
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, field
from typing import Final, Protocol
from uuid import UUID

from prometheus_client import CollectorRegistry, Counter
from sqlalchemy.ext.asyncio import AsyncSession

from sft.core import sealed
from sft.core.sealed import Column, SealedAuthenticationError, SealedValueError
from sft.data import data_keys
from sft.data.access import tenant_of
from sft.data.data_keys import KeyPurpose, WrappedKey

__all__ = [
    "APPROVAL_COMMENT",
    "DETECTOR_DEFINITION",
    "FILE_NAME",
    "FINDING_DETAIL",
    "JUSTIFICATION",
    "TRANSFER_MESSAGE",
    "UPLOAD_REQUEST_MESSAGE",
    "Column",
    "FieldDecryptError",
    "FieldKeys",
    "FieldKeysUnavailableError",
    "FieldMetrics",
    "KeyPurpose",
    "KeyService",
    "KeyServiceError",
    "SealedValueError",
    "TenantKeys",
    "install",
    "installed",
    "tenant_keys",
]

log = logging.getLogger(__name__)

FILE_NAME: Final = Column("files", "display_name_ct")
TRANSFER_MESSAGE: Final = Column("transfers", "message_ct")
UPLOAD_REQUEST_MESSAGE: Final = Column("upload_requests", "message_ct")
JUSTIFICATION: Final = Column("dlp_confirmations", "justification_ct")
APPROVAL_COMMENT: Final = Column("dlp_approval_decisions", "comment_ct")
DETECTOR_DEFINITION: Final = Column("dlp_detectors", "definition_ct")
FINDING_DETAIL: Final = Column("dlp_findings", "detail_ct")

PURPOSE_OF: Final[Mapping[Column, KeyPurpose]] = {
    FILE_NAME: KeyPurpose.FIELD,
    TRANSFER_MESSAGE: KeyPurpose.FIELD,
    UPLOAD_REQUEST_MESSAGE: KeyPurpose.FIELD,
    JUSTIFICATION: KeyPurpose.FIELD,
    APPROVAL_COMMENT: KeyPurpose.FIELD,
    DETECTOR_DEFINITION: KeyPurpose.DLP,
    FINDING_DETAIL: KeyPurpose.DLP,
}
"""Which data key seals each column (encryption and keys 3.2, 3.3)."""

CACHE_SECONDS: Final = 900.0
"""An unwrapped data key stays in memory at most 15 minutes (encryption and keys 3.2, point 4)."""
_CACHE_LIMIT: Final = 10_000


class KeyServiceError(Exception):
    """KMS refused or failed. `code` is KMS's error code or the client's error type, never a key."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class FieldKeysUnavailableError(RuntimeError):
    """This process may not use keys of this purpose, or installed no `FieldKeys` at all."""


class FieldDecryptError(RuntimeError):
    """A stored value didn't open with the caller's tenant's keys: another tenant's row, a value
    moved to another row or column, or one tampered with. Counted, logged by ID, and paged."""


class KeyService(Protocol):
    """KMS, as field encryption needs it: called directly, always with the encryption context."""

    async def generate_data_key(self, context: Mapping[str, str]) -> tuple[bytes, bytes]:
        """A new 256-bit data key: (the key, the key wrapped under the fields key)."""
        ...

    async def decrypt(self, wrapped: bytes, context: Mapping[str, str]) -> bytes:
        """Unwrap a data key."""
        ...

    async def re_encrypt(self, wrapped: bytes, context: Mapping[str, str]) -> bytes:
        """The same data key, wrapped again under the fields key's current material."""
        ...

    async def close(self) -> None: ...


@dataclass(frozen=True, slots=True)
class FieldMetrics:
    unwraps: Counter
    scope_mismatches: Counter
    plaintext_reads: Counter

    @classmethod
    def create(cls, registry: CollectorRegistry) -> FieldMetrics:
        return cls(
            unwraps=Counter(
                "field_key_unwraps",
                "Data keys unwrapped with KMS, by purpose and result (cache misses only).",
                ["purpose", "result"],
                registry=registry,
            ),
            scope_mismatches=Counter(
                "field_decrypt_scope_mismatch",
                "Sealed values that didn't open with the caller's tenant's keys: a possible "
                "isolation breach, which pages (encryption and keys 3.2).",
                ["purpose"],
                registry=registry,
            ),
            plaintext_reads=Counter(
                "field_plaintext_reads",
                "Format 0 values read, by column: rows the backfill hasn't resealed yet.",
                ["column"],
                registry=registry,
            ),
        )


def context(purpose: KeyPurpose, tenant_id: UUID) -> dict[str, str]:
    """The KMS encryption context of a tenant's data key: what the key policy checks (4.4)."""
    return {"purpose": purpose.value, "tenant_id": str(tenant_id)}


@dataclass(slots=True)
class TenantKeys:
    """One tenant's unwrapped keys of one purpose, for the length of a transaction."""

    tenant_id: UUID
    purpose: KeyPurpose
    live: int | None
    _keys: dict[int, bytes] = field(repr=False)
    _metrics: FieldMetrics = field(repr=False)

    def seal(self, column: Column, row_id: UUID, text: str) -> bytes:
        """`text` sealed for `column` of row `row_id`, under the live key, read back and checked."""
        self._check(column)
        if self.live is None:
            raise FieldKeysUnavailableError("no live key: load the keys with write=True")
        plaintext = text.encode("utf-8")
        value = sealed.encrypt(
            self._keys[self.live],
            purpose=self.purpose.value,
            tenant_id=self.tenant_id,
            column=column,
            row_id=row_id,
            version=self.live,
            plaintext=plaintext,
        )
        # The read-back check of encryption and keys 3.2: never store what we can't open.
        if self._decrypt(column, row_id, value) != plaintext:  # pragma: no cover - AES-GCM
            raise SealedValueError("a sealed value didn't read back")
        return value

    def open(self, column: Column, row_id: UUID, value: bytes) -> str:
        """The text of a stored value of `column`, row `row_id`, in this tenant's scope."""
        self._check(column)
        if sealed.value_format(value) == sealed.PLAINTEXT_FORMAT:
            self._metrics.plaintext_reads.labels(str(column)).inc()
            return sealed.plaintext_of(value).decode("utf-8")
        return self._decrypt(column, row_id, value).decode("utf-8")

    def open_optional(self, column: Column, row_id: UUID, value: bytes | None) -> str | None:
        return None if value is None else self.open(column, row_id, value)

    def _check(self, column: Column) -> None:
        if PURPOSE_OF.get(column) is not self.purpose:
            raise ValueError(f"{column} isn't sealed with the {self.purpose} key")

    def _decrypt(self, column: Column, row_id: UUID, value: bytes) -> bytes:
        version = sealed.key_version(value)
        if version is None:
            raise SealedValueError("unknown sealed-value format")
        key = self._keys.get(version)
        try:
            if key is None:
                # This tenant has no such version: most likely another tenant's row.
                raise SealedAuthenticationError("no key of that version in this tenant")
            return sealed.decrypt(
                key,
                purpose=self.purpose.value,
                tenant_id=self.tenant_id,
                column=column,
                row_id=row_id,
                value=value,
            )
        except SealedAuthenticationError:
            self._metrics.scope_mismatches.labels(self.purpose.value).inc()
            log.error(
                "a sealed value didn't open with the caller's tenant's key",
                extra={
                    "tenant_id": str(self.tenant_id),
                    "column": str(column),
                    "row_id": str(row_id),
                    "key_version": version,
                },
            )
            raise FieldDecryptError(f"{column} of row {row_id} didn't open") from None


class FieldKeys:
    """A process's data keys: unwrapped through KMS on first use, cached at most 15 minutes."""

    def __init__(
        self,
        kms: KeyService,
        metrics: FieldMetrics,
        *,
        purposes: frozenset[KeyPurpose] = frozenset(KeyPurpose),
        cache_seconds: float = CACHE_SECONDS,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if not purposes:
            raise ValueError("name the purposes this process may use")
        self.kms = kms
        self.metrics = metrics
        self.purposes = purposes
        self._cache_seconds = min(cache_seconds, CACHE_SECONDS)
        self._clock = clock
        self._cache: dict[tuple[UUID, KeyPurpose, int, bytes], tuple[bytes, float]] = {}

    def _may(self, purpose: KeyPurpose) -> None:
        if purpose not in self.purposes:
            raise FieldKeysUnavailableError(f"this workload may not use {purpose.value} keys")

    async def tenant(
        self,
        session: AsyncSession,
        tenant_id: UUID,
        purpose: KeyPurpose = KeyPurpose.FIELD,
        *,
        write: bool = False,
    ) -> TenantKeys:
        """The keys of the session's tenant, which must be `tenant_id`. With `write`, a live
        version is made first if the tenant has none."""
        self._may(purpose)
        if tenant_of(session) != tenant_id:
            raise ValueError("a transaction opens values with its own tenant's keys only")
        rows = await data_keys.list_keys(session, purpose)
        if write and not any(r.live for r in rows):
            await self.add_version(session, tenant_id, purpose, after=rows)
            rows = await data_keys.list_keys(session, purpose)
        keys = {r.version: await self.unwrap(tenant_id, purpose, r) for r in rows}
        live = next((r.version for r in rows if r.live), None)
        return TenantKeys(tenant_id, purpose, live, keys, self.metrics)

    async def add_version(
        self,
        session: AsyncSession,
        tenant_id: UUID,
        purpose: KeyPurpose,
        *,
        after: list[WrappedKey],
    ) -> bool:
        """A new live version after `after`, the versions read; False if another transaction made
        one first. A rotation retires the live one first (`sft.service.field_keys`)."""
        self._may(purpose)
        version = max((r.version for r in after), default=0) + 1
        key, wrapped = await self._kms(
            "generate", purpose, tenant_id, self.kms.generate_data_key(context(purpose, tenant_id))
        )
        made = await data_keys.insert_key(session, purpose, version=version, wrapped=wrapped)
        if made:
            self._remember(tenant_id, purpose, version, wrapped, key)
        return made

    async def unwrap(self, tenant_id: UUID, purpose: KeyPurpose, row: WrappedKey) -> bytes:
        """The data key of a stored version, from the cache or from KMS."""
        self._may(purpose)
        entry = (tenant_id, purpose, row.version, hashlib.sha256(row.wrapped).digest())
        now = self._clock()
        cached = self._cache.get(entry)
        if cached is not None and cached[1] > now:
            return cached[0]
        key = await self._kms(
            "decrypt",
            purpose,
            tenant_id,
            self.kms.decrypt(row.wrapped, context(purpose, tenant_id)),
        )
        if len(key) != sealed.KEY_BYTES:
            raise KeyServiceError("InvalidKeyLength")
        self._remember(tenant_id, purpose, row.version, row.wrapped, key)
        return key

    async def rewrap(self, tenant_id: UUID, purpose: KeyPurpose, row: WrappedKey) -> bytes:
        """The version's key wrapped again under the fields key's current material."""
        self._may(purpose)
        return await self._kms(
            "re_encrypt",
            purpose,
            tenant_id,
            self.kms.re_encrypt(row.wrapped, context(purpose, tenant_id)),
        )

    async def _kms[T](
        self, step: str, purpose: KeyPurpose, tenant_id: UUID, call: Awaitable[T]
    ) -> T:
        try:
            result = await call
        except KeyServiceError as exc:
            self.metrics.unwraps.labels(purpose.value, "error").inc()
            log.error(
                "KMS refused a data key call",
                extra={
                    "step": step,
                    "purpose": purpose.value,
                    "tenant_id": str(tenant_id),
                    "code": exc.code,
                },
            )
            raise
        if step == "decrypt":
            self.metrics.unwraps.labels(purpose.value, "ok").inc()
        return result

    def _remember(
        self, tenant_id: UUID, purpose: KeyPurpose, version: int, wrapped: bytes, key: bytes
    ) -> None:
        now = self._clock()
        if len(self._cache) >= _CACHE_LIMIT:
            self._cache = {k: v for k, v in self._cache.items() if v[1] > now}
            if len(self._cache) >= _CACHE_LIMIT:
                self._cache.clear()
        entry = (tenant_id, purpose, version, hashlib.sha256(wrapped).digest())
        self._cache[entry] = (key, now + self._cache_seconds)

    def forget(self) -> None:
        """Drop every unwrapped key, as at shutdown."""
        self._cache.clear()

    async def close(self) -> None:
        self.forget()
        await self.kms.close()


_installed: FieldKeys | None = None


def install(keys: FieldKeys | None) -> FieldKeys | None:
    """Make `keys` this process's data keys; the ones it replaces. The entry point calls it once
    at startup, and again with what it got back at shutdown."""
    global _installed
    previous, _installed = _installed, keys
    return previous


def installed() -> FieldKeys:
    if _installed is None:
        raise FieldKeysUnavailableError("this process has no field encryption keys")
    return _installed


async def tenant_keys(
    session: AsyncSession,
    tenant_id: UUID,
    purpose: KeyPurpose = KeyPurpose.FIELD,
    *,
    write: bool = False,
) -> TenantKeys:
    """The keys of the session's tenant, `tenant_id`, through this process's `FieldKeys`."""
    return await installed().tenant(session, tenant_id, purpose, write=write)
