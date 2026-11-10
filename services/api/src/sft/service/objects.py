"""Object storage, as the service layer sees it: a thin interface over S3 (ADR-0012).

The service never talks to boto3. `ObjectStore` is what it needs for uploads; `sft.runtime.s3`'s
`S3Objects` is the real one, for AWS and for S3Mock locally, and the tests use an in-memory fake.
A file is named by its storage class and key: the adapter knows which bucket pair each class
lives in, and the service never sees a bucket name.

The API's role may create, sign, list, complete and abort multipart uploads, read an object's
attributes and read the scanned version of a shareable file for a download (`FileContent`,
#180), never delete an object (abuse and rate limits 6.2): there is no delete here. Only the
lifecycle jobs delete (`StorageCleaner`, #181; architecture 4.5).
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
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

    async def part_urls(
        self,
        storage_class: StorageClass,
        key: str,
        upload_id: str,
        parts: Sequence[tuple[int, int]],
        *,
        expires_in: int = PART_URL_SECONDS,
    ) -> list[str]:
        """A pre-signed `UploadPart` URL for each `(part number, size)` in `parts`, in order, each
        with its `Content-Length` signed. Signing is local work, so all of them are made in one
        call (#166)."""
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


class FileContent(Protocol):
    """What a download needs of the files buckets (abuse and rate limits 5.6, 5.7): a byte range
    of exactly the version that was scanned, streamed through an async client."""

    def read(
        self, storage_class: StorageClass, key: str, version_id: str, *, start: int, end: int
    ) -> AsyncIterator[bytes]:
        """Bytes `start` to `end`, both included, of that version, in chunks. Raises
        `ObjectStoreError`. Close the iterator (`aclose`) to stop early."""
        ...

    async def close(self) -> None: ...


@dataclass(frozen=True, slots=True)
class StoredVersion:
    """One object version, or delete marker, in one region's bucket of a storage class."""

    region: str
    key: str
    version_id: str
    last_modified: datetime


@dataclass(frozen=True, slots=True)
class StoredUpload:
    """One unfinished multipart upload in one region's bucket of a storage class."""

    region: str
    key: str
    upload_id: str
    initiated: datetime


class StorageCleaner(Protocol):
    """What the lifecycle jobs need of the files buckets, in every region that holds a copy:
    Tokyo's, and Osaka's replicas where they exist (architecture 4.5, encryption and keys 8.1).
    Only the jobs' role may delete; it can't read what it deletes."""

    @property
    def regions(self) -> tuple[str, ...]: ...

    async def versions(self, storage_class: StorageClass, key: str) -> list[StoredVersion]:
        """Every version and delete marker of `key`, in every region."""
        ...

    async def uploads(self, storage_class: StorageClass, key: str) -> list[StoredUpload]:
        """Every unfinished multipart upload of `key`, in every region."""
        ...

    async def delete_versions(
        self, storage_class: StorageClass, versions: Sequence[StoredVersion]
    ) -> None:
        """Delete exactly these versions, each in its region. Raises `ObjectStoreError`."""
        ...

    async def abort_upload(
        self, storage_class: StorageClass, region: str, key: str, upload_id: str
    ) -> bool:
        """Abort an unfinished upload; False if it no longer exists."""
        ...

    def version_pages(self, storage_class: StorageClass) -> AsyncIterator[list[StoredVersion]]:
        """Every version under `tenants/`, in every region, one listing page at a time: the
        storage audit's listing, which holds one page in memory, never a whole bucket."""
        ...

    def upload_pages(self, storage_class: StorageClass) -> AsyncIterator[list[StoredUpload]]:
        """Every unfinished multipart upload, in every region, one listing page at a time."""
        ...

    async def close(self) -> None: ...
