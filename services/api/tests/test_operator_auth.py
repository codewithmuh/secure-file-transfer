"""Operator authentication (authn-authz 8.2): each check of the token exchange, and the token."""

from collections.abc import Callable
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import text

from operators import (
    ACCOUNT,
    AUDIENCE,
    BREAK_GLASS_ROLE,
    OPERATOR_NAME,
    OTHER_ACCOUNT,
    POLICY,
    FakeSts,
    assumed_role,
    refusing_sts,
    signed_headers,
    unreachable_sts,
)
from pg import ScratchDatabase
from sft.core.errors import ServiceUnavailable, Unauthenticated
from sft.data.audit import OperatorName, Origin
from sft.data.database import Database
from sft.service.operator_auth import (
    GET_CALLER_IDENTITY,
    TOKEN_TTL,
    Refusal,
    authenticate,
    exchange_token,
    token_hash,
)

pytestmark = pytest.mark.anyio

ORIGIN = Origin(user_agent="sft-operator-cli/test")


async def exchange(
    database: Database,
    sts: FakeSts,
    headers: dict[str, str] | None = None,
    *,
    body: str = GET_CALLER_IDENTITY,
    now: datetime | None = None,
) -> object:
    return await exchange_token(
        database,
        sts,
        POLICY,
        headers=signed_headers() if headers is None else headers,
        body=body,
        origin=ORIGIN,
        now=now,
    )


def last_refusal(db: ScratchDatabase) -> str:
    rows = db.sql(
        "SELECT details->>'reason' FROM audit_events WHERE action = 'operator.token_refused' "
        "AND tenant_id IS NULL AND outcome = 'failure' ORDER BY occurred_at DESC, id DESC LIMIT 1"
    )
    return str(rows[0][0])


async def test_a_signed_request_from_the_operator_role_gets_a_token(
    operator_db: Database, migrated_db: ScratchDatabase
) -> None:
    sts = FakeSts()
    issued = await exchange_token(
        operator_db,
        sts,
        POLICY,
        headers=signed_headers(),
        body=GET_CALLER_IDENTITY,
        origin=ORIGIN,
    )
    assert (issued.aws_account_id, issued.operator_name) == (ACCOUNT, OPERATOR_NAME)
    assert len(issued.token) >= 43
    assert issued.expires_at - datetime.now(UTC) <= TOKEN_TTL
    # Only the signed request's headers went to STS, never anything else the caller sent.
    [sent] = sts.calls
    assert set(sent) <= {
        "authorization",
        "x-amz-date",
        "x-amz-security-token",
        "x-sft-audience",
        "content-type",
    }
    assert sent["x-sft-audience"] == AUDIENCE
    # Stored as hashes only, with the operator's name; audited as a platform event.
    rows = migrated_db.sql(
        "SELECT token_hash, operator_name, aws_account_id FROM operator_sessions WHERE id = :id",
        id=issued.session_id,
    )
    assert rows == [(token_hash(issued.token), OPERATOR_NAME, ACCOUNT)]
    events = migrated_db.sql(
        "SELECT tenant_id, actor_type, actor_id, details->>'operator_name' FROM audit_events "
        "WHERE action = 'operator.token_created' AND target_id = :id",
        id=issued.session_id,
    )
    assert events == [(None, "operator", issued.session_id, OPERATOR_NAME)]

    operator = await authenticate(operator_db, issued.token)
    assert (operator.session_id, operator.name) == (issued.session_id, OPERATOR_NAME)
    assert isinstance(operator.name, OperatorName)


def without(name: str) -> dict[str, str]:
    return {k: v for k, v in signed_headers().items() if k.lower() != name}


def with_header(name: str, value: str) -> dict[str, str]:
    return {**signed_headers(), name: value}


REFUSED: list[tuple[str, Callable[[], dict[str, str]], Refusal]] = [
    ("another region", lambda: signed_headers(region="us-east-1"), Refusal.WRONG_REGION),
    ("another service", lambda: signed_headers(service="iam"), Refusal.WRONG_SERVICE),
    ("no audience", lambda: signed_headers(audience=None), Refusal.AUDIENCE),
    ("another audience", lambda: signed_headers(audience="operator-api-prod"), Refusal.AUDIENCE),
    (
        "audience not signed",
        lambda: {**signed_headers(audience=None), "X-SFT-Audience": AUDIENCE},
        Refusal.AUDIENCE,
    ),
    ("no authorization", lambda: without("authorization"), Refusal.MALFORMED),
    ("not SigV4", lambda: with_header("Authorization", "Bearer x"), Refusal.MALFORMED),
    ("a signed header missing", lambda: without("x-amz-security-token"), Refusal.MALFORMED),
    ("no date", lambda: without("x-amz-date"), Refusal.MALFORMED),
    ("a bad date", lambda: with_header("X-Amz-Date", "yesterday"), Refusal.MALFORMED),
    (
        "a header that isn't ASCII",
        lambda: with_header("X-Amz-Security-Token", "\u2026"),
        Refusal.MALFORMED,
    ),
    ("a header twice", lambda: {**signed_headers(), "AUTHORIZATION": "x"}, Refusal.MALFORMED),
]


@pytest.mark.parametrize(("case", "headers", "reason"), REFUSED, ids=[c[0] for c in REFUSED])
async def test_a_request_that_fails_a_check_is_refused_without_calling_sts(
    case: str,
    headers: Callable[[], dict[str, str]],
    reason: Refusal,
    operator_db: Database,
    migrated_db: ScratchDatabase,
) -> None:
    sts = FakeSts()
    with pytest.raises(Unauthenticated) as refused:
        await exchange(operator_db, sts, headers())
    # The same answer whatever failed; the reason is in the audit log only.
    assert refused.value.code == "credentials_invalid"
    assert sts.calls == []
    assert last_refusal(migrated_db) == reason


async def test_a_header_that_is_signed_but_not_forwarded_is_refused(
    operator_db: Database, migrated_db: ScratchDatabase
) -> None:
    headers = signed_headers()
    headers["Authorization"] = headers["Authorization"].replace(
        "SignedHeaders=", "SignedHeaders=cookie;"
    )
    headers["Cookie"] = "a=b"
    with pytest.raises(Unauthenticated):
        await exchange(operator_db, FakeSts(), headers)
    assert last_refusal(migrated_db) == Refusal.MALFORMED


async def test_a_signature_date_unlike_the_scope_date_is_refused(
    operator_db: Database, migrated_db: ScratchDatabase
) -> None:
    headers = signed_headers()
    date = headers["X-Amz-Date"]
    other = "19990101" + date[8:]
    with pytest.raises(Unauthenticated):
        await exchange(operator_db, FakeSts(), {**headers, "X-Amz-Date": other})
    assert last_refusal(migrated_db) in (Refusal.MALFORMED, Refusal.STALE)


async def test_another_body_is_refused(operator_db: Database, migrated_db: ScratchDatabase) -> None:
    with pytest.raises(Unauthenticated):
        await exchange(operator_db, FakeSts(), body="Action=GetSessionToken&Version=2011-06-15")
    assert last_refusal(migrated_db) == Refusal.MALFORMED


@pytest.mark.parametrize("skew", [timedelta(minutes=2), -timedelta(minutes=2)])
async def test_a_signature_older_or_newer_than_a_minute_is_refused(
    skew: timedelta, operator_db: Database, migrated_db: ScratchDatabase
) -> None:
    sts = FakeSts()
    with pytest.raises(Unauthenticated):
        await exchange(operator_db, sts, now=datetime.now(UTC) + skew)
    assert sts.calls == []
    assert last_refusal(migrated_db) == Refusal.STALE


async def test_a_signature_seen_before_is_refused(
    operator_db: Database, migrated_db: ScratchDatabase
) -> None:
    headers = signed_headers()
    await exchange(operator_db, FakeSts(), headers)
    sts = FakeSts()
    with pytest.raises(Unauthenticated):
        await exchange(operator_db, sts, headers)
    assert sts.calls == []
    assert last_refusal(migrated_db) == Refusal.REPLAYED


async def test_a_replay_that_races_the_first_request_is_refused_at_insert(
    operator_db: Database, migrated_db: ScratchDatabase, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Both pass the first check before either inserts: the unique hash decides.
    from sft.service import operator_auth

    async def not_seen(*_: object) -> bool:
        return False

    headers = signed_headers()
    await exchange(operator_db, FakeSts(), headers)
    monkeypatch.setattr(operator_auth, "signature_seen", not_seen)
    with pytest.raises(Unauthenticated):
        await exchange(operator_db, FakeSts(), headers)
    assert last_refusal(migrated_db) == Refusal.REPLAYED


IDENTITIES = [
    ("STS refuses the signature", refusing_sts, Refusal.STS_REFUSED),
    (
        "another account",
        lambda: FakeSts(account=OTHER_ACCOUNT, arn=assumed_role(account=OTHER_ACCOUNT)),
        Refusal.WRONG_ACCOUNT,
    ),
    (
        "an ARN of another account",
        lambda: FakeSts(arn=assumed_role(account=OTHER_ACCOUNT)),
        Refusal.WRONG_ACCOUNT,
    ),
    (
        "an IAM user",
        lambda: FakeSts(arn=f"arn:aws:iam::{ACCOUNT}:user/alice"),
        Refusal.WRONG_ACCOUNT,
    ),
    ("BreakGlass", lambda: FakeSts(arn=assumed_role(role=BREAK_GLASS_ROLE)), Refusal.WRONG_ROLE),
    (
        "a role named like it",
        lambda: FakeSts(arn=assumed_role(role=POLICY.role_name + "x")),
        Refusal.WRONG_ROLE,
    ),
    ("a bad session name", lambda: FakeSts(arn=assumed_role(name="a b")), Refusal.WRONG_ROLE),
]


@pytest.mark.parametrize(("case", "sts", "reason"), IDENTITIES, ids=[c[0] for c in IDENTITIES])
async def test_only_this_accounts_operator_role_gets_a_token(
    case: str,
    sts: Callable[[], FakeSts],
    reason: Refusal,
    operator_db: Database,
    migrated_db: ScratchDatabase,
) -> None:
    with pytest.raises(Unauthenticated) as refused:
        await exchange(operator_db, sts())
    assert refused.value.code == "credentials_invalid"
    assert last_refusal(migrated_db) == reason


async def test_sts_out_of_reach_is_a_503_and_issues_nothing(
    operator_db: Database, migrated_db: ScratchDatabase
) -> None:
    before = migrated_db.sql("SELECT count(*) FROM operator_sessions")
    with pytest.raises(ServiceUnavailable):
        await exchange(operator_db, unreachable_sts())
    assert migrated_db.sql("SELECT count(*) FROM operator_sessions") == before


@pytest.mark.parametrize("token", [None, "", "not-a-token"])
async def test_no_token_or_an_unknown_one_is_refused(
    token: str | None, operator_db: Database
) -> None:
    with pytest.raises(Unauthenticated) as refused:
        await authenticate(operator_db, token)
    assert refused.value.bearer
    expected = "authentication_required" if not token else "credentials_invalid"
    assert refused.value.code == expected


@pytest.mark.parametrize("column", ["expires_at", "revoked_at"])
async def test_an_expired_or_revoked_token_is_refused(
    column: str, operator_db: Database, migrated_db: ScratchDatabase
) -> None:
    issued = await exchange_token(
        operator_db,
        FakeSts(),
        POLICY,
        headers=signed_headers(),
        body=GET_CALLER_IDENTITY,
        origin=ORIGIN,
    )
    # As the owner: sft_operator may not change a session (no revocation route yet).
    migrated_db.sql(
        f"UPDATE operator_sessions SET {column} = now() - interval '1 second' WHERE id = :id",  # noqa: S608
        id=issued.session_id,
    )
    with pytest.raises(Unauthenticated) as refused:
        await authenticate(operator_db, issued.token)
    assert refused.value.code == "credentials_invalid"


def test_the_schema_accepts_exactly_the_body_the_service_checks() -> None:
    from typing import get_args

    from sft.api.operator.schemas import SignedStsRequest

    assert get_args(SignedStsRequest.model_fields["body"].annotation) == (GET_CALLER_IDENTITY,)


async def test_the_operator_role_reads_no_tenant_rows_in_platform_scope_but_the_directory(
    operator_db: Database,
) -> None:
    # The directory policy covers tenants alone; platform scope sets no tenant for the others.
    from sft.data.scope import Scope

    async with operator_db.transaction(Scope.platform()) as session:
        assert (await session.execute(text("SELECT 1 FROM users LIMIT 1"))).all() == []
