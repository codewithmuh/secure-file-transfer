"""Object storage, as the service layer sees it: a thin interface over S3 (ADR-0012).

The service never talks to boto3. `ObjectStore` is what it needs for uploads; `sft.runtime.s3`'s
`S3Objects` is the real one, for AWS and for S3Mock locally, and the tests use an in-memory fake.
A file is named by its storage class and key: the adapter knows which bucket pair each class
lives in, and the service never sees a bucket name.

The API's role may create, sign, list, complete and abort multipart uploads and read an object's
attributes, never delete an object (abuse and rate limits 6.2): there is no delete here.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Mapping, Sequence
from dataclasses import dataclass
from typing import Final, Protocol

from sft.data.models import StorageClass

PART_URL_SECONDS: Final = 900
"""Part URLs live 15 minutes at most; the bucket policy refuses older signatures (abuse 6.2)."""


class ObjectStoreError(Exception):
    """A call to object storage failed. `code` is S3's error code or the client's error type."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True, slots=True)
class StoredPart:
    number: int
    size: int
    etag: str


@dataclass(frozen=True, slots=True)
class ObjectAttributes:
    size: int
    version_id: str | None
    """The version `GetObjectAttributes` read; None only if the bucket isn't versioned."""


class ObjectStore(Protocol):
    async def create_multipart_upload(self, storage_class: StorageClass, key: str) -> str:
        """Start a multipart upload, encrypted with the files key; its upload ID."""
        ...

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
        """A pre-signed `UploadPart` URL for one part, with its `Content-Length` signed."""
        ...

    async def list_parts(
        self, storage_class: StorageClass, key: str, upload_id: str
    ) -> list[StoredPart] | None:
        """Every part S3 holds for the upload, by number; None if the upload no longer exists."""
        ...

    async def complete_multipart_upload(
        self, storage_class: StorageClass, key: str, upload_id: str, parts: Sequence[StoredPart]
    ) -> None:
        """Assemble the upload from exactly `parts`, in order."""
        ...

    async def object_attributes(
        self, storage_class: StorageClass, key: str
    ) -> ObjectAttributes | None:
        """The current version's size and version ID; None if there is no object."""
        ...

    async def abort_multipart_upload(
        self, storage_class: StorageClass, key: str, upload_id: str
    ) -> None:
        """Drop an unfinished upload and its parts. Only for an upload no row refers to."""
        ...

    async def close(self) -> None: ...


SCAN_TAG: Final = "scan"
"""The object tag the scan worker sets once a result is recorded (ADR-0019). The API's role may
read only objects tagged `clean` or `unscannable_allowed`; the scan worker's only untagged ones."""


class ScannedObjects(Protocol):
    """What the scan worker needs of the files buckets (ADR-0019, ADR-0022): read the version
    recorded at completion once, and tag it with the result. It never deletes or writes bytes."""

    def read_version(
        self, storage_class: StorageClass, key: str, version_id: str
    ) -> AsyncIterator[bytes]:
        """The bytes of exactly that version, in chunks, never the latest one."""
        ...

    async def object_tags(
        self, storage_class: StorageClass, key: str, version_id: str
    ) -> Mapping[str, str]:
        """The version's tags, such as the ones GuardDuty sets."""
        ...

    async def put_object_tags(
        self, storage_class: StorageClass, key: str, version_id: str, tags: Mapping[str, str]
    ) -> None:
        """Replace the version's tags with `tags`."""
        ...

    async def close(self) -> None: ...
