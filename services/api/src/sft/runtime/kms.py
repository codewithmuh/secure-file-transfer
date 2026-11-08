"""KMS behind `sft.service.fields.KeyService`: the fields key, called directly (encryption and keys
3.2, 3.3, 4.4; #236, #233).

`AwsKms` is the real one. Every call names the fields key (its alias `alias/sft/<env>/fields` or
its ARN) and the encryption context `{"purpose", "tenant_id"}`, which the key policy checks: the
API may use `field-dek` and `dlp-dek`, the scan worker `dlp-dek` only, and each needs `tenant_id`.
boto3 runs in this adapter's own small thread pool, never in the event loop, as for S3
(`sft.runtime.s3`). The Osaka API names the same alias and reaches Osaka's replica of the
multi-Region key, so it unwraps without Tokyo (3.2, point 6).

`LocalKms` is the local stand-in, for the compose stack and the tests, where there is no KMS: it
wraps data keys with AES-256-GCM under one local key, binding the encryption context as KMS does,
so a key unwrapped with another tenant's or purpose's context fails, and it refuses the purposes
its process's role wouldn't be allowed (the scan worker's `dlp-dek` only). It exists so the code
path that reaches KMS is exercised end to end without AWS; running it against real KMS is pending
the AWS run. Its wrapping key is a fixed, public value derived in code: it protects nothing and
isn't meant to. `FIELDS_KMS_KEY_ID=local` selects it; the chart never sets that (deploy/tests),
and `open_kms` logs a warning whenever it is chosen, so a pod that had it would show it.

No error names a key, and nothing here logs a value.
"""

from __future__ import annotations

import asyncio
import functools
import hashlib
import json
import logging
import os
from collections.abc import Callable, Mapping
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Final, Protocol

import boto3
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from prometheus_client import CollectorRegistry

from sft.service.fields import FieldKeys, FieldMetrics, KeyPurpose, KeyServiceError

log = logging.getLogger(__name__)

_KEY_SPEC: Final = "AES_256"
_LOCAL_PREFIX: Final = b"sft-local-kms/1"
_NONCE_BYTES: Final = 12
LOCAL_KEY_ID: Final = "local"
_LOCAL_KEY: Final = hashlib.sha256(b"sft local KMS stand-in: public, protects nothing").digest()


class _KmsClient(Protocol):
    """The three calls of boto3's KMS client this adapter makes."""

    def generate_data_key(self, **kwargs: Any) -> Mapping[str, Any]: ...
    def decrypt(self, **kwargs: Any) -> Mapping[str, Any]: ...
    def re_encrypt(self, **kwargs: Any) -> Mapping[str, Any]: ...


def _error(exc: ClientError | BotoCoreError) -> KeyServiceError:
    if isinstance(exc, ClientError):
        return KeyServiceError(str(exc.response.get("Error", {}).get("Code", "ClientError")))
    return KeyServiceError(type(exc).__name__)


class AwsKms:
    """`KeyService` through boto3, each call in this adapter's own thread pool."""

    def __init__(self, client: _KmsClient, key_id: str, *, threads: int = 4) -> None:
        self._client = client
        self._key_id = key_id
        self._pool = ThreadPoolExecutor(max_workers=threads, thread_name_prefix="kms")

    @classmethod
    def create(
        cls, *, region: str, key_id: str, endpoint_url: str | None = None, threads: int = 4
    ) -> AwsKms:
        # Short timeouts and few retries: an unwrap sits in a request's path, and a cache miss
        # should cost tens of milliseconds, not seconds.
        config = Config(
            region_name=region,
            connect_timeout=2,
            read_timeout=5,
            retries={"mode": "standard", "total_max_attempts": 3},
        )
        client: _KmsClient = boto3.client("kms", config=config, endpoint_url=endpoint_url)
        return cls(client, key_id, threads=threads)

    async def _run(
        self, call: Callable[..., Mapping[str, Any]], **kwargs: Any
    ) -> Mapping[str, Any]:
        loop = asyncio.get_running_loop()
        try:
            return await loop.run_in_executor(self._pool, functools.partial(call, **kwargs))
        except (ClientError, BotoCoreError) as exc:
            raise _error(exc) from None

    async def generate_data_key(self, context: Mapping[str, str]) -> tuple[bytes, bytes]:
        answer = await self._run(
            self._client.generate_data_key,
            KeyId=self._key_id,
            KeySpec=_KEY_SPEC,
            EncryptionContext=dict(context),
        )
        return bytes(answer["Plaintext"]), bytes(answer["CiphertextBlob"])

    async def decrypt(self, wrapped: bytes, context: Mapping[str, str]) -> bytes:
        # Naming the key makes KMS refuse a blob wrapped under any other key.
        answer = await self._run(
            self._client.decrypt,
            KeyId=self._key_id,
            CiphertextBlob=wrapped,
            EncryptionContext=dict(context),
        )
        return bytes(answer["Plaintext"])

    async def re_encrypt(self, wrapped: bytes, context: Mapping[str, str]) -> bytes:
        answer = await self._run(
            self._client.re_encrypt,
            CiphertextBlob=wrapped,
            SourceKeyId=self._key_id,
            SourceEncryptionContext=dict(context),
            DestinationKeyId=self._key_id,
            DestinationEncryptionContext=dict(context),
        )
        return bytes(answer["CiphertextBlob"])

    async def close(self) -> None:
        self._pool.shutdown(wait=False, cancel_futures=True)


class LocalKms:
    """The local stand-in: data keys wrapped under one local key, bound to their context.

    `purposes` mimics the key policy: a context whose purpose isn't listed is refused with
    `AccessDeniedException`, as KMS would refuse the scan worker a `field-dek` unwrap. A context
    without `purpose` and `tenant_id` is refused too, as the policy's conditions require both.
    Each re-wrap draws a new nonce, so a re-wrapped key differs from the one it replaces."""

    def __init__(self, key: bytes = _LOCAL_KEY, *, purposes: frozenset[str] | None = None) -> None:
        if len(key) != 32:
            raise ValueError("the local stand-in's key is 256 bits")
        self._aead = AESGCM(key)
        self._purposes = purposes

    def _aad(self, context: Mapping[str, str]) -> bytes:
        purpose = context.get("purpose")
        if purpose is None or "tenant_id" not in context:
            raise KeyServiceError("AccessDeniedException")
        if self._purposes is not None and purpose not in self._purposes:
            raise KeyServiceError("AccessDeniedException")
        return _LOCAL_PREFIX + json.dumps(dict(context), sort_keys=True).encode()

    def _wrap(self, key: bytes, context: Mapping[str, str]) -> bytes:
        nonce = os.urandom(_NONCE_BYTES)
        return _LOCAL_PREFIX + nonce + self._aead.encrypt(nonce, key, self._aad(context))

    def _unwrap(self, wrapped: bytes, context: Mapping[str, str]) -> bytes:
        aad = self._aad(context)
        if not wrapped.startswith(_LOCAL_PREFIX):
            raise KeyServiceError("InvalidCiphertextException")
        body = wrapped[len(_LOCAL_PREFIX) :]
        try:
            return self._aead.decrypt(body[:_NONCE_BYTES], body[_NONCE_BYTES:], aad)
        except InvalidTag:
            raise KeyServiceError("InvalidCiphertextException") from None

    async def generate_data_key(self, context: Mapping[str, str]) -> tuple[bytes, bytes]:
        key = os.urandom(32)
        return key, self._wrap(key, context)

    async def decrypt(self, wrapped: bytes, context: Mapping[str, str]) -> bytes:
        return self._unwrap(wrapped, context)

    async def re_encrypt(self, wrapped: bytes, context: Mapping[str, str]) -> bytes:
        return self._wrap(self._unwrap(wrapped, context), context)

    async def close(self) -> None:
        return None


def open_kms(
    *, key_id: str, region: str, purposes: frozenset[str] | None = None
) -> AwsKms | LocalKms:
    """The fields key the settings name: KMS, or the local stand-in for `local`. `purposes` is
    what the stand-in allows, as the key policy would for this process's role."""
    if key_id == LOCAL_KEY_ID:
        log.warning("field encryption uses the local KMS stand-in, which protects nothing")
        return LocalKms(purposes=purposes)
    return AwsKms.create(region=region, key_id=key_id)


def open_field_keys(
    *,
    key_id: str,
    region: str,
    registry: CollectorRegistry,
    purposes: frozenset[KeyPurpose] = frozenset(KeyPurpose),
) -> FieldKeys:
    """This process's data keys, limited to the purposes its role may use (4.3)."""
    kms = open_kms(key_id=key_id, region=region, purposes=frozenset(p.value for p in purposes))
    return FieldKeys(kms, FieldMetrics.create(registry), purposes=purposes)
