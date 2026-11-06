"""S3 behind `sft.service.objects.ObjectStore` (ADR-0012; delivery plan risk "local emulators differ
from AWS").

`S3Objects` is the real store, for AWS and for S3Mock locally; one integration test runs it against
S3Mock (tests/test_s3_s3mock.py). It holds the two files buckets of one region, the standard one and
the large-files one, and picks between them by the file's storage class, so callers never name a
bucket. Multipart uploads are encrypted with SSE-KMS under the files key with S3 Bucket Keys; S3Mock
takes the key by its bare ID only (local development 4).

**boto3 in a thread pool, not an async client**, for the reasons `sft.workers.queues` gives: each
call runs in this adapter's own small pool, never in the event loop. Signing a part URL is local
work, but it runs there too, so a slow credential refresh can't block the loop.

Timeouts are short and retries few: completion calls S3 between two short transactions (data model
3.1), and a request should answer within seconds. Checksums are computed only when S3 requires one,
so a part URL carries no checksum header the browser would have to repeat.

It lives in `sft.runtime` because both entry points need it: the API for uploads
(`sft.service.objects.ObjectStore`), and the scan worker, which reads the recorded version of a
file once and tags it with its result (`ScannedObjects`, ADR-0019).
"""

from __future__ import annotations

import asyncio
import functools
from collections.abc import AsyncIterator, Callable, Mapping, Sequence
from concurrent.futures import ThreadPoolExecutor
from typing import TYPE_CHECKING, Any, Final

import boto3
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError

from sft.data.models import StorageClass
from sft.service.objects import (
    PART_URL_SECONDS,
    ObjectAttributes,
    ObjectStoreError,
    StoredPart,
)

if TYPE_CHECKING:
    from types_boto3_s3.client import S3Client

_MISSING: Final = frozenset({"NoSuchUpload", "NoSuchKey", "404", "NotFound"})
READ_CHUNK: Final = 1024 * 1024
"""Bytes per read of a streamed object: the scan worker tees each chunk to clamd and the
inspector, so memory stays a few chunks per scan, whatever the file's size."""


def _error(exc: ClientError | BotoCoreError) -> ObjectStoreError:
    if isinstance(exc, ClientError):
        return ObjectStoreError(str(exc.response.get("Error", {}).get("Code", "ClientError")))
    return ObjectStoreError(type(exc).__name__)


class S3Objects:
    """`ObjectStore` through boto3, each call in this adapter's own thread pool."""

    def __init__(
        self,
        client: S3Client,
        buckets: Mapping[StorageClass, str],
        *,
        kms_key_id: str | None,
        threads: int,
    ) -> None:
        if set(buckets) != set(StorageClass):
            raise ValueError("name a bucket for every storage class")
        self._client = client
        self._buckets = dict(buckets)
        self._kms_key_id = kms_key_id
        self._executor = ThreadPoolExecutor(max_workers=threads, thread_name_prefix="s3")

    @classmethod
    def create(
        cls,
        *,
        region: str,
        files_bucket: str,
        large_files_bucket: str,
        kms_key_id: str | None = None,
        endpoint_url: str | None = None,
        threads: int = 8,
    ) -> S3Objects:
        """A store for one region's files buckets. Credentials come from the pod's IAM role.
        `kms_key_id` is the files key, needed only to start uploads (the API)."""
        config = Config(
            region_name=region,
            signature_version="s3v4",
            connect_timeout=1,
            read_timeout=5,
            retries={"mode": "standard", "max_attempts": 2},
            max_pool_connections=threads,
            request_checksum_calculation="when_required",
            response_checksum_validation="when_required",
            # S3Mock serves buckets by path; AWS by virtual host, the SDK's default there.
            s3={"addressing_style": "path" if endpoint_url else "virtual"},
        )
        client = boto3.session.Session().client("s3", endpoint_url=endpoint_url, config=config)
        buckets = {StorageClass.STANDARD: files_bucket, StorageClass.LARGE: large_files_bucket}
        return cls(client, buckets, kms_key_id=kms_key_id, threads=threads)

    async def _call[T](self, fn: Callable[..., T], /, **kwargs: object) -> T:
        loop = asyncio.get_running_loop()
        try:
            return await loop.run_in_executor(self._executor, functools.partial(fn, **kwargs))
        except (ClientError, BotoCoreError) as exc:
            raise _error(exc) from exc

    def _bucket(self, storage_class: StorageClass) -> str:
        return self._buckets[StorageClass(storage_class)]

    async def create_multipart_upload(self, storage_class: StorageClass, key: str) -> str:
        if self._kms_key_id is None:
            raise ValueError("this store has no files key, so it starts no uploads")
        response = await self._call(
            self._client.create_multipart_upload,
            Bucket=self._bucket(storage_class),
            Key=key,
            ContentType="application/octet-stream",  # never the declared type (abuse 6.4)
            ServerSideEncryption="aws:kms",
            SSEKMSKeyId=self._kms_key_id,
            BucketKeyEnabled=True,
        )
        return response["UploadId"]

    async def part_url(
        self,
        storage_class: StorageClass,
        key: str,
        upload_id: str,
        *,
        part_number: int,
        size: int,
        expires_in: int = PART_URL_SECONDS,
    ) -> str:
        if not 1 <= expires_in <= PART_URL_SECONDS:
            raise ValueError("a part URL lives at most 15 minutes")
        return await self._call(
            self._client.generate_presigned_url,
            ClientMethod="upload_part",
            Params={
                "Bucket": self._bucket(storage_class),
                "Key": key,
                "UploadId": upload_id,
                "PartNumber": part_number,
                "ContentLength": size,
            },
            ExpiresIn=expires_in,
            HttpMethod="PUT",
        )

    async def list_parts(
        self, storage_class: StorageClass, key: str, upload_id: str
    ) -> list[StoredPart] | None:
        parts: list[StoredPart] = []
        marker = 0
        while True:
            try:
                response = await self._call(
                    self._client.list_parts,
                    Bucket=self._bucket(storage_class),
                    Key=key,
                    UploadId=upload_id,
                    MaxParts=1000,
                    PartNumberMarker=marker,
                )
            except ObjectStoreError as exc:
                if exc.code in _MISSING:
                    return None
                raise
            parts += [
                StoredPart(p["PartNumber"], p["Size"], p["ETag"]) for p in response.get("Parts", [])
            ]
            if not response.get("IsTruncated"):
                return parts
            marker = int(response.get("NextPartNumberMarker", 0))

    async def complete_multipart_upload(
        self, storage_class: StorageClass, key: str, upload_id: str, parts: Sequence[StoredPart]
    ) -> None:
        await self._call(
            self._client.complete_multipart_upload,
            Bucket=self._bucket(storage_class),
            Key=key,
            UploadId=upload_id,
            MultipartUpload={"Parts": [{"PartNumber": p.number, "ETag": p.etag} for p in parts]},
        )

    async def object_attributes(
        self, storage_class: StorageClass, key: str
    ) -> ObjectAttributes | None:
        try:
            response = await self._call(
                self._client.get_object_attributes,
                Bucket=self._bucket(storage_class),
                Key=key,
                ObjectAttributes=["ObjectSize"],
            )
        except ObjectStoreError as exc:
            if exc.code in _MISSING:
                return None
            raise
        return ObjectAttributes(
            size=int(response["ObjectSize"]), version_id=response.get("VersionId")
        )

    async def abort_multipart_upload(
        self, storage_class: StorageClass, key: str, upload_id: str
    ) -> None:
        await self._call(
            self._client.abort_multipart_upload,
            Bucket=self._bucket(storage_class),
            Key=key,
            UploadId=upload_id,
        )

    async def read_version(
        self, storage_class: StorageClass, key: str, version_id: str
    ) -> AsyncIterator[bytes]:
        """`GetObject` for exactly `version_id`, in chunks; each read runs in the thread pool."""
        response = await self._call(
            self._client.get_object,
            Bucket=self._bucket(storage_class),
            Key=key,
            VersionId=version_id,
        )
        body: Any = response["Body"]
        loop = asyncio.get_running_loop()
        try:
            while True:
                try:
                    chunk: bytes = await loop.run_in_executor(self._executor, body.read, READ_CHUNK)
                except (ClientError, BotoCoreError) as exc:
                    raise _error(exc) from exc
                if not chunk:
                    return
                yield chunk
        finally:
            body.close()

    async def object_tags(
        self, storage_class: StorageClass, key: str, version_id: str
    ) -> Mapping[str, str]:
        response = await self._call(
            self._client.get_object_tagging,
            Bucket=self._bucket(storage_class),
            Key=key,
            VersionId=version_id,
        )
        return {tag["Key"]: tag["Value"] for tag in response.get("TagSet", [])}

    async def put_object_tags(
        self, storage_class: StorageClass, key: str, version_id: str, tags: Mapping[str, str]
    ) -> None:
        await self._call(
            self._client.put_object_tagging,
            Bucket=self._bucket(storage_class),
            Key=key,
            VersionId=version_id,
            Tagging={"TagSet": [{"Key": k, "Value": v} for k, v in sorted(tags.items())]},
        )

    async def close(self) -> None:
        """Wait for calls in flight, then close the client. Call it once, at shutdown."""
        await asyncio.to_thread(self._executor.shutdown, wait=True)
        self._client.close()
