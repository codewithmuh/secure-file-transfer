"""An in-memory `ObjectStore` for the upload routes' tests and the authorization matrix (#114).

`FakeObjects` keeps uploads and objects in dictionaries, so a test can act between completion's
phases (`before_assemble`) or make every call fail (`failing`). `put_part` stands in for the
client's PUT to a part URL. tests/test_s3_s3mock.py runs the real adapter against S3Mock.
"""

from __future__ import annotations

import asyncio
import uuid
from collections.abc import AsyncIterator, Callable, Sequence
from dataclasses import dataclass, field

from sft.data.models import StorageClass
from sft.service.objects import ObjectAttributes, ObjectStoreError, StoredPart


@dataclass
class FakeObjects:
    uploads: dict[str, dict[int, int]] = field(default_factory=dict)
    objects: dict[str, int] = field(default_factory=dict)
    aborted: list[str] = field(default_factory=list)
    failing: bool = False
    before_assemble: Callable[[], None] | None = None

    def _check(self) -> None:
        if self.failing:
            raise ObjectStoreError("ServiceUnavailable")

    async def create_multipart_upload(self, storage_class: StorageClass, key: str) -> str:
        self._check()
        upload_id = f"upload-{uuid.uuid4()}"
        self.uploads[upload_id] = {}
        return upload_id

    async def part_urls(
        self,
        storage_class: StorageClass,
        key: str,
        upload_id: str,
        parts: Sequence[tuple[int, int]],
        *,
        expires_in: int = 900,
    ) -> list[str]:
        self._check()
        return [
            f"https://s3.test/{key}?uploadId={upload_id}&partNumber={number}&size={size}"
            for number, size in parts
        ]

    def put_part(self, upload_id: str, number: int, size: int) -> None:
        self.uploads.setdefault(upload_id, {})[number] = size

    async def list_parts(
        self, storage_class: StorageClass, key: str, upload_id: str
    ) -> list[StoredPart] | None:
        self._check()
        if self.before_assemble is not None:
            self.before_assemble()
        if upload_id not in self.uploads:
            return None
        return [StoredPart(n, s, f"etag-{n}") for n, s in sorted(self.uploads[upload_id].items())]

    async def complete_multipart_upload(
        self, storage_class: StorageClass, key: str, upload_id: str, parts: Sequence[StoredPart]
    ) -> None:
        self.objects[key] = sum(p.size for p in parts)
        del self.uploads[upload_id]

    async def object_attributes(
        self, storage_class: StorageClass, key: str
    ) -> ObjectAttributes | None:
        size = self.objects.get(key)
        return None if size is None else ObjectAttributes(size, "version-1")

    async def abort_multipart_upload(
        self, storage_class: StorageClass, key: str, upload_id: str
    ) -> None:
        self.aborted.append(upload_id)
        self.uploads.pop(upload_id, None)

    async def close(self) -> None:
        return None


@dataclass
class FakeContent:
    """An in-memory `FileContent` for the download tests (#180): each version's bytes by key, sent
    in `chunk`-byte pieces with an optional `delay` before each, so a test can watch a stream's
    re-checks. tests/test_s3_s3mock.py runs the real reader against S3Mock."""

    objects: dict[tuple[str, str], bytes] = field(default_factory=dict)
    chunk: int = 64 * 1024
    delay: float = 0.0
    failing: bool = False
    fail_on_close: bool = False
    """Closing a read part-way raises, as an HTTP client can when its peer went away."""
    reads: list[tuple[str, str, int, int]] = field(default_factory=list)

    def put(self, key: str, version_id: str, data: bytes) -> None:
        self.objects[(key, version_id)] = data

    async def read(
        self, storage_class: StorageClass, key: str, version_id: str, *, start: int, end: int
    ) -> AsyncIterator[bytes]:
        self.reads.append((key, version_id, start, end))
        if self.failing:
            raise ObjectStoreError("ServiceUnavailable")
        data = self.objects[(key, version_id)][start : end + 1]
        try:
            for offset in range(0, len(data), self.chunk):
                if self.delay:
                    await asyncio.sleep(self.delay)
                yield data[offset : offset + self.chunk]
        except GeneratorExit:
            if self.fail_on_close:
                raise ObjectStoreError("ReadError") from None
            raise

    async def close(self) -> None:
        return None
