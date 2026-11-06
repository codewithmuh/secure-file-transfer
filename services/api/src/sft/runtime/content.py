"""Download bytes from the files buckets with an async client (`sft.service.objects.FileContent`;
abuse and rate limits 5.6, 5.7; #180).

boto3 is synchronous (ADR-0002), and a stream lasts minutes, so a thread per stream would cap a pod
at its thread pool. The content routes therefore fetch with httpx's async client instead, which
the API already uses for OIDC: boto3 signs a `GetObject` URL for exactly the scanned version, in
process and in this adapter's small thread pool (signing can refresh the pod's credentials), and
httpx streams it with the `Range` of the request. The signed URL lives a minute and never leaves
the pod; it is the API's own credential, used at once, not a bearer URL handed to a client.

SSE-KMS objects need SigV4, which the URL carries. S3Mock, locally, checks no signature.
"""

from __future__ import annotations

import asyncio
import functools
from collections.abc import AsyncIterator, Mapping
from concurrent.futures import ThreadPoolExecutor
from typing import TYPE_CHECKING, Final

import boto3
import httpx2 as httpx
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError

from sft.data.models import StorageClass
from sft.service.objects import ObjectStoreError

if TYPE_CHECKING:
    from types_boto3_s3.client import S3Client

CHUNK: Final = 64 * 1024
"""Bytes per chunk sent: small enough that a stream re-checks often, large enough to be cheap."""
URL_SECONDS: Final = 60


class S3Content:
    """`FileContent` over one region's files buckets."""

    def __init__(
        self, client: S3Client, buckets: Mapping[StorageClass, str], http: httpx.AsyncClient
    ) -> None:
        if set(buckets) != set(StorageClass):
            raise ValueError("name a bucket for every storage class")
        self._client = client
        self._buckets = dict(buckets)
        self._http = http
        self._executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="s3-sign")

    @classmethod
    def create(
        cls,
        *,
        region: str,
        files_bucket: str,
        large_files_bucket: str,
        endpoint_url: str | None = None,
        max_streams: int = 100,
    ) -> S3Content:
        config = Config(
            region_name=region,
            signature_version="s3v4",
            s3={"addressing_style": "path" if endpoint_url else "virtual"},
        )
        client = boto3.session.Session().client("s3", endpoint_url=endpoint_url, config=config)
        http = httpx.AsyncClient(
            timeout=httpx.Timeout(10.0, read=60.0),
            limits=httpx.Limits(max_connections=max_streams, max_keepalive_connections=20),
            follow_redirects=False,
            trust_env=False,
        )
        buckets = {StorageClass.STANDARD: files_bucket, StorageClass.LARGE: large_files_bucket}
        return cls(client, buckets, http)

    async def _url(self, storage_class: StorageClass, key: str, version_id: str) -> str:
        sign = functools.partial(
            self._client.generate_presigned_url,
            ClientMethod="get_object",
            Params={
                "Bucket": self._buckets[StorageClass(storage_class)],
                "Key": key,
                "VersionId": version_id,
            },
            ExpiresIn=URL_SECONDS,
            HttpMethod="GET",
        )
        try:
            return await asyncio.get_running_loop().run_in_executor(self._executor, sign)
        except (ClientError, BotoCoreError) as exc:
            raise ObjectStoreError(type(exc).__name__) from None

    async def read(
        self, storage_class: StorageClass, key: str, version_id: str, *, start: int, end: int
    ) -> AsyncIterator[bytes]:
        url = await self._url(storage_class, key, version_id)
        headers = {"Range": f"bytes={start}-{end}"}
        try:
            async with self._http.stream("GET", url, headers=headers) as response:
                if response.status_code not in (200, 206):
                    raise ObjectStoreError(str(response.status_code))
                async for chunk in response.aiter_bytes(CHUNK):
                    yield chunk
        except httpx.HTTPError as exc:
            raise ObjectStoreError(type(exc).__name__) from None

    async def close(self) -> None:
        await self._http.aclose()
        await asyncio.to_thread(self._executor.shutdown, wait=True)
        self._client.close()
