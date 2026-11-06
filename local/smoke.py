# /// script
# requires-python = ">=3.13"
# dependencies = [
#   "boto3==1.43.120",
#   "psycopg[binary]==3.3.6",
#   "requests==2.34.2",
#   "valkey==6.2.0",
# ]
# [tool.uv]
# exclude-newer = "2026-10-28T00:00:00Z"
# ///
"""Smoke checks for the local stack: one real round trip per service, from the host.

Run with `make smoke` after `make up`. Settings come from the environment, with the
defaults of .env.example. Every credential here is local-only and works only against
the compose stack.
"""

from __future__ import annotations

import base64
import hashlib
import html
import json
import os
import re
import secrets
import smtplib
import socket
import struct
import subprocess
import sys
import time
import uuid
from collections.abc import Callable
from email.message import EmailMessage
from urllib.parse import parse_qs, urlparse

import boto3
import psycopg
import requests
import valkey
from botocore.config import Config
from botocore.exceptions import ClientError

ENV = {
    # The API's own role, which row-level security applies to, and the server's superuser.
    "DATABASE_URL": "postgresql+psycopg://sft_api:test-only-password@127.0.0.1:5432/sft",
    "LOCAL_POSTGRES_URL": "postgresql://sft:sft-local-only@127.0.0.1:5432/sft",
    "AWS_REGION": "ap-northeast-1",
    "AWS_ACCESS_KEY_ID": "local-only",
    "AWS_SECRET_ACCESS_KEY": "local-only",
    "S3_ENDPOINT_URL": "http://127.0.0.1:9090",
    "S3_FILES_BUCKET": "sft-local-files",
    "S3_LARGE_FILES_BUCKET": "sft-local-large-files",
    "S3_AUDIT_BUCKET": "sft-local-audit-archive",
    "S3_FILES_KMS_KEY_ID": "00000000-0000-4000-8000-000000000001",
    "SQS_ENDPOINT_URL": "http://127.0.0.1:9324",
    "SQS_QUEUE_PREFIX": "sft-local-",
    "VALKEY_URL": "redis://sft-local:local-only-valkey-password@127.0.0.1:6379/0",
    "SMTP_HOST": "127.0.0.1",
    "SMTP_PORT": "1025",
    "MAIL_CATCHER_URL": "http://127.0.0.1:8025",
    "CLAMD_HOST": "127.0.0.1",
    "CLAMD_PORT": "3310",
    "OIDC_ISSUER": "http://localhost:8180/realms/sft",
    "OIDC_CLIENT_ID": "sft-api-local",
    "OIDC_CLIENT_SECRET": "local-only-oidc-client-secret",
    "OIDC_REDIRECT_URI": "http://localhost:8000/v1/auth/callback",
    "OIDC_TEST_EMAIL": "dev.member@example.com",
    "OIDC_TEST_PASSWORD": "local-only-member-password",
}
cfg = {key: os.environ.get(key, default) for key, default in ENV.items()}

# The EICAR test file, decoded at run time so no antivirus flags this script.
EICAR = base64.b64decode(
    "WDVPIVAlQEFQWzRcUFpYNTQoUF4pN0NDKTd9JEVJQ0FSLVNUQU5EQVJELUFO"
    "VElWSVJVUy1URVNULUZJTEUhJEgrSCo="
)
QUEUES = [
    "scan-small",
    "scan-large",
    "notify",
    "signin-events",
    "ses-events",
    "guardduty-results",
    "ses-tenant-status",
]


def aws(service: str):
    return boto3.client(
        service,
        endpoint_url=cfg[f"{service.upper()}_ENDPOINT_URL"],
        region_name=cfg["AWS_REGION"],
        aws_access_key_id=cfg["AWS_ACCESS_KEY_ID"],
        aws_secret_access_key=cfg["AWS_SECRET_ACCESS_KEY"],
        config=Config(signature_version="s3v4", s3={"addressing_style": "path"}),
    )


def postgres(variable: str) -> psycopg.Connection:
    url = cfg[variable].replace("postgresql+psycopg://", "postgresql://", 1)
    return psycopg.connect(url, connect_timeout=5)


def check_postgres() -> str:
    with postgres("LOCAL_POSTGRES_URL") as conn:
        one = conn.execute("SELECT 1").fetchone()
        version = conn.execute("SHOW server_version").fetchone()
        # db-migrate ran: the database has a revision (alembic_version belongs to sft_owner).
        revision = conn.execute("SELECT version_num FROM alembic_version").fetchone()
    assert one == (1,), one
    assert version and version[0].startswith("17."), version
    assert revision, "the database has no migration revision"
    return f"SELECT 1 ok, PostgreSQL {version[0]}, migrated to {revision[0]}"


def check_api_role() -> str:
    """The API's login reads no tenant's row without a scope, and its own row with one (ADR-0020)."""
    tenant = uuid.uuid4()
    with postgres("LOCAL_POSTGRES_URL") as admin:
        admin.execute(
            "INSERT INTO tenants (id, name, status) VALUES (%s, 'smoke check', 'active')",
            (tenant,),
        )
        admin.commit()
        try:
            with postgres("DATABASE_URL") as conn:
                role = conn.execute(
                    "SELECT rolname, rolsuper, rolbypassrls FROM pg_roles "
                    "WHERE rolname = current_user"
                ).fetchone()
                assert role == ("sft_api", False, False), role
                unscoped = conn.execute("SELECT count(*) FROM tenants").fetchone()
                assert unscoped == (0,), (
                    f"sft_api read {unscoped} tenant rows without a scope"
                )
                conn.rollback()
                # The scope the API sets at the start of every transaction (sft.data.database).
                conn.execute(
                    "SELECT set_config('app.scope', 'tenant', true), "
                    "set_config('app.tenant_id', %s, true)",
                    (str(tenant),),
                )
                scoped = conn.execute("SELECT id FROM tenants").fetchall()
                assert scoped == [(tenant,)], (
                    f"in its tenant's scope sft_api read {scoped}"
                )
        finally:
            admin.execute("DELETE FROM tenants WHERE id = %s", (tenant,))
            admin.commit()
    return (
        "sft_api, no superuser or BYPASSRLS; 0 tenant rows unscoped, its own row scoped"
    )


def check_s3() -> str:
    s3 = aws("s3")
    bucket, key = cfg["S3_FILES_BUCKET"], f"tenants/smoke/{uuid.uuid4()}"
    audit = cfg["S3_AUDIT_BUCKET"]
    sse = {"ServerSideEncryption": "aws:kms", "SSEKMSKeyId": cfg["S3_FILES_KMS_KEY_ID"]}
    for name in (bucket, cfg["S3_LARGE_FILES_BUCKET"], audit):
        status = s3.get_bucket_versioning(Bucket=name).get("Status")
        assert status == "Enabled", (name, status)
    lock = s3.get_object_lock_configuration(Bucket=audit)["ObjectLockConfiguration"]
    assert lock["ObjectLockEnabled"] == "Enabled", lock
    try:
        other_key = {
            "ServerSideEncryption": "aws:kms",
            "SSEKMSKeyId": str(uuid.uuid4()),
        }
        s3.put_object(Bucket=bucket, Key=f"{key}-other-key", Body=b"x", **other_key)
        raise AssertionError("an upload naming another KMS key was accepted")
    except ClientError:
        pass

    # A multipart upload through pre-signed part URLs, as the browser sends it
    # (architecture 4.1).
    parts = [os.urandom(5 * 1024 * 1024), os.urandom(1024)]
    upload_id = s3.create_multipart_upload(Bucket=bucket, Key=key, **sse)["UploadId"]
    for number, data in enumerate(parts, start=1):
        part = {
            "Bucket": bucket,
            "Key": key,
            "UploadId": upload_id,
            "PartNumber": number,
        }
        url = s3.generate_presigned_url("upload_part", Params=part, ExpiresIn=900)
        response = requests.put(url, data=data, timeout=30)
        assert response.status_code == 200, (response.status_code, response.text[:200])
    listed = s3.list_parts(Bucket=bucket, Key=key, UploadId=upload_id)["Parts"]
    done = [{"PartNumber": p["PartNumber"], "ETag": p["ETag"]} for p in listed]
    s3.complete_multipart_upload(
        Bucket=bucket, Key=key, UploadId=upload_id, MultipartUpload={"Parts": done}
    )
    attrs = s3.get_object_attributes(
        Bucket=bucket, Key=key, ObjectAttributes=["ObjectSize"]
    )
    assert attrs["ObjectSize"] == sum(map(len, parts)), attrs
    first_version = attrs["VersionId"]

    # A second write makes a new version, and the first stays readable by its ID: the
    # scan pins the version it checked (threat model T-32).
    s3.put_object(Bucket=bucket, Key=key, Body=b"second", **sse)
    pinned = s3.get_object(Bucket=bucket, Key=key, VersionId=first_version)
    assert pinned["ContentLength"] == sum(map(len, parts)), pinned["ContentLength"]
    tags = {"TagSet": [{"Key": "scan", "Value": "clean"}]}
    s3.put_object_tagging(Bucket=bucket, Key=key, Tagging=tags)

    params = {"Bucket": bucket, "Key": key}
    url = s3.generate_presigned_url("get_object", Params=params, ExpiresIn=60)
    response = requests.get(url, timeout=10)
    assert response.status_code == 200, response.status_code
    assert response.content == b"second", response.content[:20]

    versions = s3.list_object_versions(Bucket=bucket, Prefix=key).get("Versions", [])
    for version in versions:
        s3.delete_object(Bucket=bucket, Key=key, VersionId=version["VersionId"])
    return "versioning, Object Lock, KMS key check, pre-signed multipart upload and get"


def check_sqs() -> str:
    sqs = aws("sqs")
    urls = {}
    for name in QUEUES:
        for queue in (name, f"{name}-dlq"):
            full = cfg["SQS_QUEUE_PREFIX"] + queue
            urls[queue] = sqs.get_queue_url(QueueName=full)["QueueUrl"]
    redrive = sqs.get_queue_attributes(
        QueueUrl=urls["scan-small"], AttributeNames=["RedrivePolicy"]
    )
    assert "scan-small-dlq" in redrive["Attributes"]["RedrivePolicy"], redrive

    # A queue of its own: the scan workers consume the work queues, so they would take its messages.
    url = sqs.create_queue(
        QueueName=f"{cfg['SQS_QUEUE_PREFIX']}smoke-{uuid.uuid4().hex[:8]}"
    )["QueueUrl"]
    try:
        return _round_trip(sqs, url, len(urls))
    finally:
        sqs.delete_queue(QueueUrl=url)


def _round_trip(sqs, url: str, queues: int) -> str:
    body = json.dumps({"outbox_id": str(uuid.uuid4())})
    sqs.send_message(QueueUrl=url, MessageBody=body, MessageGroupId="smoke-tenant")
    sqs.send_message(QueueUrl=url, MessageBody="delayed", DelaySeconds=2)
    received = sqs.receive_message(
        QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=1
    )
    messages = received.get("Messages", [])
    assert [m["Body"] for m in messages] == [body], "the delayed message came too early"
    sqs.delete_message(QueueUrl=url, ReceiptHandle=messages[0]["ReceiptHandle"])

    start = time.monotonic()
    while time.monotonic() - start < 10:
        received = sqs.receive_message(QueueUrl=url, WaitTimeSeconds=1)
        if messages := received.get("Messages"):
            assert messages[0]["Body"] == "delayed", messages[0]["Body"]
            sqs.delete_message(QueueUrl=url, ReceiptHandle=messages[0]["ReceiptHandle"])
            break
    else:
        raise AssertionError("the delayed message never became visible")
    delay = time.monotonic() - start
    return f"{queues} queues; send and receive; delayed message after {delay:.1f}s"


def check_valkey() -> str:
    client = valkey.Valkey.from_url(cfg["VALKEY_URL"], socket_timeout=3)
    assert client.ping() is True
    key = f"rl:smoke:test:{uuid.uuid4()}"
    assert client.set(key, "1", ex=5) is True and client.ttl(key) > 0
    client.delete(key)
    host = client.connection_pool.connection_kwargs["host"]
    try:
        valkey.Valkey(host=host, port=6379, socket_timeout=3).ping()
        raise AssertionError("the default user still answers without a password")
    except valkey.AuthenticationError:
        pass
    except valkey.ResponseError as error:
        assert "NOAUTH" in str(error), error
    return "PING ok as sft-local; unauthenticated access refused"


def clamd(command: bytes, payload: bytes | None = None) -> bytes:
    address = (cfg["CLAMD_HOST"], int(cfg["CLAMD_PORT"]))
    with socket.create_connection(address, timeout=30) as conn:
        conn.sendall(b"z" + command + b"\0")
        if payload is not None:
            chunk = struct.pack("!L", len(payload)) + payload
            conn.sendall(chunk + struct.pack("!L", 0))
        reply = b""
        while data := conn.recv(4096):
            reply += data
    return reply.rstrip(b"\0")


def check_clamd() -> str:
    assert clamd(b"PING") == b"PONG"
    clean = clamd(b"INSTREAM", b"just some bytes")
    assert clean == b"stream: OK", clean
    infected = clamd(b"INSTREAM", EICAR)
    assert infected.endswith(b"FOUND"), infected
    signature = infected.decode().split(": ", 1)[1]
    return f"PONG; clean stream OK; EICAR detected ({signature})"


# Run inside the inspector's container: it must reach neither the database, the counter store nor anything outside.
INSPECTOR_PROBE = """
import socket, sys
for host, port in (("postgres", 5432), ("valkey", 6379), ("1.1.1.1", 443)):
    try:
        socket.create_connection((host, port), 3).close()
    except OSError:
        continue
    sys.exit(f"reached {host}:{port}")
"""

# Run inside a scan worker's container: one small text through the inspector's protocol and sandbox.
WORKER_PROBE = """
import asyncio
from sft.dlp import client
from sft.dlp.detect import BUILTIN_DETECTORS

async def main():
    data = b"nothing sensitive here"
    # The same calls the scan worker makes: connect, then inspect over the socket, which we close.
    sock = await client.connect("inspector", 8070)
    async def body():
        yield data
    with sock:
        answer = await client.inspect(
            sock, size=len(data), body=body(), builtin_detectors=BUILTIN_DETECTORS
        )
    print(answer.state)

asyncio.run(main())
"""


def in_container(service: str, script: str) -> str:
    done = subprocess.run(
        ["docker", "compose", "exec", "-T", service, "python", "-c", script],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert done.returncode == 0, (
        done.stderr.strip()[-300:] or done.stdout.strip()[-300:]
    )
    return done.stdout.strip()


def check_inspector() -> str:
    # ADR-0022: no egress at all, and no database; only the scan workers reach it.
    in_container("inspector", INSPECTOR_PROBE)
    state = in_container("scan-worker-small", WORKER_PROBE)
    assert state == "inspected", state
    return "no route to the database, the counter store or out; a scan worker's file inspected"


def check_mail() -> str:
    subject = f"sft smoke {uuid.uuid4()}"
    message = EmailMessage()
    message["From"] = "no-reply@mail.sft.localhost"
    message["To"] = "recipient@example.com"
    message["Subject"] = subject
    message.set_content("Local smoke check.")
    with smtplib.SMTP(cfg["SMTP_HOST"], int(cfg["SMTP_PORT"]), timeout=5) as smtp:
        smtp.send_message(message)
    api = cfg["MAIL_CATCHER_URL"]
    query = {"query": f'subject:"{subject}"'}
    for _ in range(20):
        found = requests.get(f"{api}/api/v1/search", params=query, timeout=5)
        found.raise_for_status()
        if found.json()["messages"]:
            break
        time.sleep(0.25)
    else:
        raise AssertionError("the message never reached the catcher")
    ids = [m["ID"] for m in found.json()["messages"]]
    requests.delete(f"{api}/api/v1/messages", json={"IDs": ids}, timeout=5)
    return "sent over SMTP, read back from the catcher's API"


def check_oidc() -> str:
    issuer = cfg["OIDC_ISSUER"]
    discovery_url = f"{issuer}/.well-known/openid-configuration"
    discovery = requests.get(discovery_url, timeout=10).json()
    assert discovery["issuer"] == issuer, discovery["issuer"]
    authorize = discovery["authorization_endpoint"]
    client = (cfg["OIDC_CLIENT_ID"], cfg["OIDC_CLIENT_SECRET"])

    # The authorization code flow with PKCE (S256), nonce and prompt=login, as the API
    # runs it (authn-authz 2.4).
    verifier = secrets.token_urlsafe(48)
    digest = hashlib.sha256(verifier.encode()).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
    state, nonce = secrets.token_urlsafe(16), secrets.token_urlsafe(16)
    params = {
        "client_id": cfg["OIDC_CLIENT_ID"],
        "redirect_uri": cfg["OIDC_REDIRECT_URI"],
        "response_type": "code",
        "scope": "openid email",
        "state": state,
        "nonce": nonce,
        "prompt": "login",
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    }
    no_pkce = {k: v for k, v in params.items() if not k.startswith("code_challenge")}
    refused = requests.get(authorize, params=no_pkce, allow_redirects=False, timeout=10)
    location = refused.headers.get("Location", "")
    assert "error=invalid_request" in location, "PKCE is not enforced"

    page = requests.get(authorize, params=params, timeout=10)
    page.raise_for_status()
    form = re.search(r'<form[^>]*id="kc-form-login"[^>]*action="([^"]+)"', page.text)
    assert form, "no login form"
    # Keycloak marks its sign-in cookies Secure. Browsers send them to http://localhost
    # but requests doesn't, so pass them on as a browser would.
    cookies = "; ".join(f"{cookie.name}={cookie.value}" for cookie in page.cookies)
    credentials = {
        "username": cfg["OIDC_TEST_EMAIL"],
        "password": cfg["OIDC_TEST_PASSWORD"],
    }
    login = requests.post(
        html.unescape(form.group(1)),
        data=credentials,
        headers={"Cookie": cookies},
        allow_redirects=False,
        timeout=10,
    )
    callback = parse_qs(urlparse(login.headers.get("Location", "")).query)
    assert callback.get("state") == [state], f"sign-in failed ({login.status_code})"

    grant = {
        "grant_type": "authorization_code",
        "code": callback["code"][0],
        "redirect_uri": cfg["OIDC_REDIRECT_URI"],
        "code_verifier": verifier,
    }
    tokens = requests.post(
        discovery["token_endpoint"], data=grant, auth=client, timeout=10
    )
    tokens.raise_for_status()
    body = tokens.json()
    payload = body["id_token"].split(".")[1]
    claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
    expected = {
        "iss": issuer,
        "aud": cfg["OIDC_CLIENT_ID"],
        "nonce": nonce,
        "token_use": "id",
    }
    for claim, value in expected.items():
        assert claims.get(claim) == value, (claim, claims.get(claim))
    assert claims.get("custom:tenant_id") and claims.get("cognito:username"), claims

    # The API revokes the refresh token at once and keeps nothing (ADR-0016).
    revoke = {"token": body["refresh_token"], "token_type_hint": "refresh_token"}
    revoked = requests.post(
        discovery["revocation_endpoint"], data=revoke, auth=client, timeout=10
    )
    assert revoked.status_code == 200, revoked.status_code
    user = claims["cognito:username"]
    return f"discovery; code flow with PKCE as {user}; refresh token revoked"


CHECKS: dict[str, Callable[[], str]] = {
    "postgres": check_postgres,
    "api-role": check_api_role,
    "s3": check_s3,
    "sqs": check_sqs,
    "valkey": check_valkey,
    "clamd": check_clamd,
    "inspector": check_inspector,
    "mail": check_mail,
    "oidc": check_oidc,
}


def main() -> int:
    failed = 0
    for name, check in CHECKS.items():
        start = time.monotonic()
        try:
            detail = check()
            print(f"ok    {name:9} {detail} ({time.monotonic() - start:.1f}s)")
        except Exception as error:  # noqa: BLE001 - report every failure, exit non-zero
            failed += 1
            print(f"FAIL  {name:9} {type(error).__name__}: {error}")
    print(f"{len(CHECKS) - failed}/{len(CHECKS)} services passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
