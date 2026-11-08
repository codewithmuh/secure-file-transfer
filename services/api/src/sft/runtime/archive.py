"""The audit archive's buckets behind `sft.service.audit_archive.ArchiveStore` (#177, ADR-0012).

`S3AuditArchive` holds one S3 client per region, Tokyo and Osaka, each for that region's Object
Lock archive bucket. One integration test runs it against S3Mock (tests/test_audit_archive.py).

- **A conditional write.** `PutObject` with `If-None-Match: *`: S3 refuses it with `412` when the
  key holds an object already, which here means "the record is there": a retry rewrites nothing.
  The API's role has `s3:PutObject` on the archive and nothing else (infra eks-cluster), so a
  `HeadObject` first isn't possible, and isn't needed.
- **A checksum on every write.** S3 refuses a `PutObject` to a bucket with Object Lock retention
  unless it carries a checksum or `Content-MD5`, so each write sends its SHA-256.
- **Encryption** is the bucket's default, SSE-KMS under the audit key with S3 Bucket Keys
  (encryption and keys 4.1); the request names no key.
- **boto3 in a thread pool**, as for the files buckets (`sft.runtime.s3`), with short timeouts and
  few retries, because the API answers only once both writes are done.

In AWS the Osaka client reaches Osaka's S3 from Tokyo's VPC through the network layer's cross-Region
S3 endpoint (ADR-0021); both Regions' archive admit the API's role (modules/audit-archive, #185).
"""

from __future__ import annotations

import asyncio
import functools
from collections.abc import Callable, Mapping
from concurrent.futures import ThreadPoolExecutor
from typing import TYPE_CHECKING, Final

import boto3
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError

from sft.service.audit_archive import ArchiveWriteError, Region

if TYPE_CHECKING:
    from types_boto3_s3.client import S3Client

_ALREADY_THERE: Final = frozenset({"PreconditionFailed", "412"})


class S3AuditArchive:
    """`ArchiveStore` through boto3: one client and one bucket per region."""

    def __init__(
        self,
        clients: Mapping[Region, S3Client],
        buckets: Mapping[Region, str],
        *,
        threads: int = 4,
    ) -> None:
        if set(clients) != set(buckets) or Region.TOKYO not in buckets:
            raise ValueError("name a client and a bucket for each region, Tokyo at least")
        self._clients = dict(clients)
        self._buckets = dict(buckets)
        self._executor = ThreadPoolExecutor(max_workers=threads, thread_name_prefix="archive")

    @classmethod
    def create(
        cls,
        buckets: Mapping[Region, str],
        endpoints: Mapping[Region, str | None] | None = None,
        *,
        threads: int = 4,
    ) -> S3AuditArchive:
        """A store for each region's bucket. Credentials come from the pod's IAM role."""
        clients = {}
        for region in buckets:
            endpoint = (endpoints or {}).get(region)
            config = Config(
                region_name=region.value,
                signature_version="s3v4",
                connect_timeout=1,
                read_timeout=3,
                retries={"mode": "standard", "max_attempts": 2},
                max_pool_connections=threads,
                request_checksum_calculation="when_required",
                response_checksum_validation="when_required",
                s3={"addressing_style": "path" if endpoint else "virtual"},
            )
            clients[region] = boto3.session.Session().client(
                "s3", endpoint_url=endpoint, config=config
            )
        return cls(clients, buckets, threads=threads)

    @property
    def regions(self) -> tuple[Region, ...]:
        return tuple(region for region in Region if region in self._buckets)

    async def _call[T](self, fn: Callable[..., T], /, **kwargs: object) -> T:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(self._executor, functools.partial(fn, **kwargs))

    async def put_once(self, region: Region, key: str, body: bytes) -> bool:
        client = self._clients.get(region)
        if client is None:
            raise ArchiveWriteError("NoArchiveInRegion")
        try:
            await self._call(
                client.put_object,
                Bucket=self._buckets[region],
                Key=key,
                Body=body,
                ContentType="application/json",
                IfNoneMatch="*",
                ChecksumAlgorithm="SHA256",
            )
        except ClientError as exc:
            code = str(exc.response.get("Error", {}).get("Code", "ClientError"))
            if code in _ALREADY_THERE:
                return False
            raise ArchiveWriteError(code) from None
        except BotoCoreError as exc:
            raise ArchiveWriteError(type(exc).__name__) from None
        return True

    async def close(self) -> None:
        await asyncio.to_thread(self._executor.shutdown, wait=True)
        for client in self._clients.values():
            client.close()
