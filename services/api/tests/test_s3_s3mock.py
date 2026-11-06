"""The S3 adapter, and a whole upload through the routes, against S3Mock (ADR-0012, #114).

`TEST_S3_ENDPOINT_URL` names an S3Mock server, e.g. http://127.0.0.1:9090, started with the files
key of compose.yaml among its valid KMS keys. Each test makes its own versioned buckets there.
Without the variable the tests are skipped locally; in CI they fail instead.
"""

from __future__ import annotations

import os
import secrets
import uuid
from collections.abc import AsyncIterator, Iterator

import boto3
import httpx2 as httpx
import pytest

from member_fixtures import app_for
from pg import ScratchDatabase
from sft.data.database import Database
from sft.data.models import Role, StorageClass
from sft.runtime.content import S3Content
from sft.runtime.s3 import S3Objects
from sft.service.objects import ObjectStoreError
from test_transfers import MIB, add_tenant

pytestmark = pytest.mark.anyio

ENDPOINT_VARIABLE = "TEST_S3_ENDPOINT_URL"
REGION = "ap-northeast-1"
# The files key's bare ID, as S3Mock takes it (local development 4); compose.yaml lists its ARN.
FILES_KEY = "00000000-0000-4000-8000-000000000001"
# S3Mock checks no credentials, but the SDK wants some. Obviously fake.
FAKE_CREDENTIALS = {"AWS_ACCESS_KEY_ID": "local-fake", "AWS_SECRET_ACCESS_KEY": "local-fake"}


@pytest.fixture(scope="session")
def endpoint() -> str:
    url = os.environ.get(ENDPOINT_VARIABLE)
    if not url:
        if os.environ.get("CI"):
            pytest.fail(f"{ENDPOINT_VARIABLE} must be set in CI")
        pytest.skip(f"set {ENDPOINT_VARIABLE} to an S3Mock URL")
    return url


@pytest.fixture
def buckets(endpoint: str, monkeypatch: pytest.MonkeyPatch) -> Iterator[tuple[str, str]]:
    """A versioned standard and large-files bucket of this test's own, as Terraform makes them."""
    for name, value in FAKE_CREDENTIALS.items():
        monkeypatch.setenv(name, value)
    client = boto3.client("s3", endpoint_url=endpoint, region_name=REGION)
    suffix = secrets.token_hex(4)
    names = (f"sft-test-files-{suffix}", f"sft-test-large-files-{suffix}")
    for name in names:
        client.create_bucket(Bucket=name, CreateBucketConfiguration={"LocationConstraint": REGION})
        client.put_bucket_versioning(Bucket=name, VersioningConfiguration={"Status": "Enabled"})
    yield names
    client.close()


@pytest.fixture
async def objects(endpoint: str, buckets: tuple[str, str]) -> AsyncIterator[S3Objects]:
    store = S3Objects.create(
        region=REGION,
        files_bucket=buckets[0],
        large_files_bucket=buckets[1],
        kms_key_id=FILES_KEY,
        endpoint_url=endpoint,
        threads=2,
    )
    yield store
    await store.close()


async def put(client: httpx.AsyncClient, url: str, data: bytes) -> None:
    response = await client.put(url, content=data)
    assert response.status_code == 200, response.text


async def test_the_adapter_uploads_assembles_and_reads_a_versioned_object(
    objects: S3Objects,
) -> None:
    key = f"tenants/{uuid.uuid4()}/files/{uuid.uuid4()}"
    upload_id = await objects.create_multipart_upload(StorageClass.STANDARD, key)
    first, last = os.urandom(5 * MIB), os.urandom(10)
    async with httpx.AsyncClient() as client:
        for number, data in ((1, first), (2, last)):
            url = await objects.part_url(
                StorageClass.STANDARD, key, upload_id, part_number=number, size=len(data)
            )
            await put(client, url, data)
    parts = await objects.list_parts(StorageClass.STANDARD, key, upload_id)
    assert parts is not None
    assert [(p.number, p.size) for p in parts] == [(1, 5 * MIB), (2, 10)]
    await objects.complete_multipart_upload(StorageClass.STANDARD, key, upload_id, parts)
    attributes = await objects.object_attributes(StorageClass.STANDARD, key)
    assert attributes is not None
    assert attributes.size == 5 * MIB + 10
    assert attributes.version_id
    # The upload is gone once assembled; a missing object reads as None.
    assert await objects.list_parts(StorageClass.STANDARD, key, upload_id) is None
    assert await objects.object_attributes(StorageClass.STANDARD, key + "-none") is None


async def test_an_aborted_upload_is_gone(objects: S3Objects) -> None:
    key = f"tenants/{uuid.uuid4()}/files/{uuid.uuid4()}"
    upload_id = await objects.create_multipart_upload(StorageClass.LARGE, key)
    await objects.abort_multipart_upload(StorageClass.LARGE, key, upload_id)
    assert await objects.list_parts(StorageClass.LARGE, key, upload_id) is None


async def test_a_part_url_lives_15_minutes_at_most(objects: S3Objects) -> None:
    with pytest.raises(ValueError, match="15 minutes"):
        await objects.part_url(
            StorageClass.STANDARD, "k", "u", part_number=1, size=1, expires_in=901
        )


async def test_a_missing_bucket_is_an_object_store_error(endpoint: str) -> None:
    store = S3Objects.create(
        region=REGION,
        files_bucket="sft-test-no-such-bucket",
        large_files_bucket="sft-test-no-such-bucket",
        kms_key_id=FILES_KEY,
        endpoint_url=endpoint,
        threads=1,
    )
    try:
        with pytest.raises(ObjectStoreError):
            await store.create_multipart_upload(StorageClass.STANDARD, "k")
    finally:
        await store.close()


async def test_a_file_uploads_in_parts_through_the_api_and_reaches_scanning(
    migrated_db: ScratchDatabase, api_db: Database, objects: S3Objects
) -> None:
    # Acceptance criterion 1 of #114: the routes, PostgreSQL and S3Mock, end to end.
    _, users = add_tenant(migrated_db, ("alice", Role.MEMBER))
    app = app_for(api_db, lambda: users["alice"])
    app.state.objects = objects
    data = os.urandom(6 * MIB + 3)
    transport = httpx.ASGITransport(app=app)
    async with (
        httpx.AsyncClient(transport=transport, base_url="http://api.test") as api,
        httpx.AsyncClient() as s3,
    ):
        response = await api.post(
            "/v1/transfers", json={"recipients": [{"email": "partner@example.test"}]}
        )
        transfer_id = response.json()["id"]
        response = await api.post(
            f"/v1/transfers/{transfer_id}/files",
            json={"display_name": "data.bin", "size": len(data)},
        )
        assert response.status_code == 201, response.text
        file = response.json()
        assert file["upload"] == {"part_size": 5 * MIB, "part_count": 2}
        response = await api.post(f"/v1/files/{file['id']}/parts", json={"part_numbers": [1, 2]})
        for part in response.json()["parts"]:
            start = (part["part_number"] - 1) * 5 * MIB
            await put(s3, part["url"], data[start : start + part["size"]])
        listed = (await api.get(f"/v1/files/{file['id']}/parts")).json()
        assert [p["part_number"] for p in listed["parts"]] == [1, 2]
        response = await api.post(f"/v1/files/{file['id']}/complete")
    assert response.status_code == 200, response.text
    assert response.json()["state"] == "scanning"
    [(state, actual_size, version)] = migrated_db.sql(
        "SELECT state, actual_size, s3_version_id FROM files WHERE id = :id",
        id=uuid.UUID(file["id"]),
    )
    assert (state, actual_size) == ("scanning", len(data))
    assert version
    [(topic,)] = migrated_db.sql(
        "SELECT topic FROM outbox WHERE payload->>'file_id' = :id", id=file["id"]
    )
    assert topic == "file.scan"


async def test_the_content_reader_streams_a_range_of_exactly_the_scanned_version(
    endpoint: str, buckets: tuple[str, str]
) -> None:
    """Downloads read with an async client (#180, abuse 5.7): a signed GET of one version."""
    client = boto3.client("s3", endpoint_url=endpoint, region_name=REGION)
    key = f"tenants/{uuid.uuid4()}/files/{uuid.uuid4()}"
    first = client.put_object(Bucket=buckets[0], Key=key, Body=b"0123456789")["VersionId"]
    client.put_object(Bucket=buckets[0], Key=key, Body=b"later version")
    client.close()
    content = S3Content.create(
        region=REGION,
        files_bucket=buckets[0],
        large_files_bucket=buckets[1],
        endpoint_url=endpoint,
    )
    try:
        read = content.read(StorageClass.STANDARD, key, first, start=2, end=5)
        assert b"".join([chunk async for chunk in read]) == b"2345"
        whole = content.read(StorageClass.STANDARD, key, first, start=0, end=9)
        assert b"".join([chunk async for chunk in whole]) == b"0123456789"
        missing = content.read(StorageClass.STANDARD, key + "x", first, start=0, end=1)
        with pytest.raises(ObjectStoreError):
            await anext(missing)
    finally:
        await content.close()
