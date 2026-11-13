"""The daily SSO provider drift check (#239; FR-26; authn and authz 2.5, 2.6): each tenant's
recorded provider against both user pools.

The acceptance criterion: the check reports a provider missing or changed in either pool, with an
alert (promtool tests in deploy/alerts/tests/sso.test.yaml). The pools are fakes here: reading
Cognito is pending the AWS run.
"""

from __future__ import annotations

import asyncio
import uuid
from collections.abc import Mapping, Sequence
from typing import Any

import pytest
from prometheus_client import CollectorRegistry, Counter

from member_fixtures import seed_tenant
from pg import ScratchDatabase
from sft.api.operator import jobs
from sft.core.settings import IdpClient
from sft.data.database import Database
from sft.data.sso_drift import RecordedProvider
from sft.runtime.sso_directory import CognitoProviderDirectory
from sft.service import sso_drift
from sft.service.sso_drift import (
    OIDC_ATTRIBUTES,
    SAML_ATTRIBUTES,
    Aspect,
    DriftResult,
    PoolProvider,
    PoolRegion,
    PoolSnapshot,
    Problem,
    compare,
)
from test_operator_api import settings_for

TOKYO, OSAKA = PoolRegion.TOKYO, PoolRegion.OSAKA
ISSUER = "https://idp.corp.example"


def recorded(kind: str = "oidc", status: str = "active", **fields: Any) -> RecordedProvider:
    tenant_id = uuid.uuid4()
    values: dict[str, Any] = {
        "connection_id": uuid.uuid4(),
        "tenant_id": tenant_id,
        "kind": kind,
        "provider_name": tenant_id.hex,
        "issuer": ISSUER if kind == "oidc" else "",
        "status": status,
        **fields,
    }
    return RecordedProvider(**values)


def provider(row: RecordedProvider, **fields: Any) -> PoolProvider:
    values: dict[str, Any] = {
        "name": row.provider_name,
        "type": row.kind.upper(),
        "issuer": ISSUER + "/" if row.kind == "oidc" else None,
        "attribute_mapping": dict(OIDC_ATTRIBUTES if row.kind == "oidc" else SAML_ATTRIBUTES),
        **fields,
    }
    return PoolProvider(**values)


def snapshot(*providers: PoolProvider, enabled: Sequence[str] | None = None) -> PoolSnapshot:
    names = [p.name for p in providers]
    return PoolSnapshot(
        {p.name: p for p in providers}, frozenset(names if enabled is None else enabled)
    )


def test_a_pool_that_matches_the_record_reports_nothing() -> None:
    oidc, saml = recorded(), recorded("saml")
    saml_found = provider(saml, attribute_mapping={**SAML_ATTRIBUTES, "username": "sub"})
    assert compare(TOKYO, [oidc, saml], snapshot(provider(oidc), saml_found)) == []


def test_a_missing_provider_and_an_unrecorded_one_are_reported() -> None:
    kept, lost = recorded(), recorded()
    stray = uuid.uuid4()
    pool = snapshot(provider(kept), PoolProvider(name=stray.hex, type="OIDC"))
    findings = compare(OSAKA, [kept, lost], pool)
    assert [(f.pool, f.problem, f.provider_name, f.tenant_id) for f in findings] == [
        (OSAKA, Problem.MISSING, lost.provider_name, lost.tenant_id),
        (OSAKA, Problem.UNRECORDED, stray.hex, stray),
    ]
    assert findings[0].connection_id == lost.connection_id
    # A provider not named after a tenant is still unrecorded, with no tenant.
    [odd] = compare(OSAKA, [], snapshot(PoolProvider(name="Hand-made", type="SAML")))
    assert (odd.problem, odd.tenant_id) == (Problem.UNRECORDED, None)


@pytest.mark.parametrize(
    ("change", "aspect"),
    [
        ({"type": "SAML"}, Aspect.TYPE),
        ({"issuer": "https://evil.example"}, Aspect.ISSUER),
        ({"attribute_mapping": {**OIDC_ATTRIBUTES, "email": "upn"}}, Aspect.ATTRIBUTE_MAPPING),
        (
            {"attribute_mapping": {**OIDC_ATTRIBUTES, "custom:tenant_id": "tid"}},
            Aspect.ATTRIBUTE_MAPPING,
        ),
        ({"identifiers": ["corp.example"]}, Aspect.IDENTIFIERS),
    ],
)
def test_a_changed_provider_names_what_changed(change: dict[str, Any], aspect: Aspect) -> None:
    row = recorded()
    [finding] = compare(TOKYO, [row], snapshot(provider(row, **change)))
    assert (finding.problem, finding.aspects) == (Problem.CHANGED, (aspect,))


def test_a_provider_the_app_client_doesnt_offer_has_changed() -> None:
    row = recorded()
    [finding] = compare(TOKYO, [row], snapshot(provider(row), enabled=[]))
    assert finding.aspects == (Aspect.NOT_ENABLED,)


def test_an_inactive_connection_is_recorded_but_not_checked() -> None:
    row = recorded(status="inactive")
    assert compare(TOKYO, [row], snapshot()) == []
    assert compare(TOKYO, [row], snapshot(provider(row, type="SAML"))) == []


class FakeDirectory:
    def __init__(self, snapshots: Mapping[PoolRegion, PoolSnapshot]) -> None:
        self.snapshots = dict(snapshots)

    @property
    def pools(self) -> Sequence[PoolRegion]:
        return tuple(self.snapshots)

    async def snapshot(self, pool: PoolRegion) -> PoolSnapshot:
        return self.snapshots[pool]


def connect(db: ScratchDatabase, tenant_id: uuid.UUID, *, status: str = "active") -> uuid.UUID:
    connection = uuid.uuid4()
    db.sql(
        "INSERT INTO idp_connections (id, tenant_id, kind, provider_name, issuer, status) "
        "VALUES (:id, :t, 'oidc', :p, :issuer, :status)",
        id=connection,
        t=tenant_id,
        p=tenant_id.hex,
        issuer=ISSUER,
        status=status,
    )
    return connection


@pytest.mark.anyio
async def test_the_check_reads_every_tenants_record_and_audits_what_differs(
    migrated_db: ScratchDatabase, operator_db: Database
) -> None:
    ok, changed = seed_tenant(migrated_db), seed_tenant(migrated_db)
    connect(migrated_db, ok.id)
    changed_connection = connect(migrated_db, changed.id)
    good = PoolProvider(
        name=ok.id.hex, type="OIDC", issuer=ISSUER, attribute_mapping=OIDC_ATTRIBUTES
    )
    bad = PoolProvider(
        name=changed.id.hex, type="OIDC", issuer="https://other.example", attribute_mapping={}
    )
    directory = FakeDirectory({TOKYO: snapshot(good, bad), OSAKA: snapshot(good)})

    result = await sso_drift.check(operator_db, directory)
    mine = {
        (f.pool, f.problem, f.aspects)
        for f in result.findings
        if f.tenant_id in (ok.id, changed.id)
    }
    assert mine == {
        (TOKYO, Problem.CHANGED, (Aspect.ISSUER, Aspect.ATTRIBUTE_MAPPING)),
        (OSAKA, Problem.MISSING, ()),
    }
    assert result.checked >= 2
    events = migrated_db.sql(
        "SELECT details->>'pool', details->>'problem', details ? 'issuer', tenant_id IS NULL "
        "FROM audit_events WHERE action = 'sso_provider.drift_found' AND target_id = :c "
        "ORDER BY details->>'pool'",
        c=changed_connection,
    )
    assert events == [
        ("ap-northeast-1", "changed", True, True),
        ("ap-northeast-3", "missing", False, True),
    ]
    [(details,)] = migrated_db.sql(
        "SELECT details FROM audit_events WHERE action = 'sso_provider.drift_checked' "
        "ORDER BY occurred_at DESC, id DESC LIMIT 1"
    )
    assert details["job"] == "sso_drift_check"
    assert details["findings"] == len(result.findings)
    counts = result.counts()
    assert set(counts) == {(pool, problem) for pool in (TOKYO, OSAKA) for problem in Problem}


def test_the_platform_read_reaches_tenants_connections_only(migrated_db: ScratchDatabase) -> None:
    # The pool's own connection (no tenant) is never among them: revision 0038's policy.
    rows = migrated_db.sql(
        "SELECT count(*) FROM pg_policies WHERE tablename = 'idp_connections' "
        "AND policyname = 'sso_drift_read' AND qual LIKE '%tenant_id IS NOT NULL%'"
    )
    assert rows == [(1,)]


class FakeCognito:
    """The three Cognito calls the directory makes, with a provider's secret in its details."""

    def __init__(self) -> None:
        self.calls: list[str] = []

    def list_identity_providers(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append(f"list:{kwargs.get('NextToken')}")
        if kwargs.get("NextToken") is None:
            return {"Providers": [{"ProviderName": "a" * 32}], "NextToken": "page-2"}
        return {"Providers": [{"ProviderName": "b" * 32}]}

    def describe_identity_provider(self, **kwargs: Any) -> dict[str, Any]:
        name = kwargs["ProviderName"]
        return {
            "IdentityProvider": {
                "ProviderName": name,
                "ProviderType": "OIDC",
                "ProviderDetails": {"oidc_issuer": ISSUER, "client_secret": "test-only"},
                "AttributeMapping": dict(OIDC_ATTRIBUTES),
                "IdpIdentifiers": [],
            }
        }

    def describe_user_pool_client(self, **kwargs: Any) -> dict[str, Any]:
        return {"UserPoolClient": {"SupportedIdentityProviders": ["COGNITO", "a" * 32]}}


@pytest.mark.anyio
async def test_the_cognito_directory_reads_every_page_and_keeps_no_secret() -> None:
    pool = IdpClient(region="ap-northeast-3", user_pool_id="ap-northeast-3_abc", client_id="xyz")
    client = FakeCognito()
    directory = CognitoProviderDirectory([pool], clients={"ap-northeast-3": client})
    assert directory.pools == (OSAKA,)
    found = await directory.snapshot(OSAKA)
    assert set(found.providers) == {"a" * 32, "b" * 32}
    assert found.enabled == frozenset({"COGNITO", "a" * 32})
    assert client.calls == ["list:None", "list:page-2"]
    assert "test-only" not in repr(found)


def test_the_metrics_follow_the_check() -> None:
    registry = CollectorRegistry()
    metrics = jobs.DriftMetrics.create(registry, (TOKYO, OSAKA))
    labels = {"pool": "ap-northeast-3", "problem": "missing"}
    assert registry.get_sample_value("sft_sso_provider_drift", labels) == 0
    row = recorded()
    findings = compare(OSAKA, [row], snapshot())
    metrics.observe(DriftResult((TOKYO, OSAKA), 1, findings))
    assert registry.get_sample_value("sft_sso_provider_drift", labels) == 1
    assert (
        registry.get_sample_value("sft_sso_provider_drift", {**labels, "pool": "ap-northeast-1"})
        == 0
    )
    stamp = registry.get_sample_value("sft_sso_drift_check_last_success_timestamp_seconds")
    assert stamp is not None
    assert stamp > 0


@pytest.mark.anyio
async def test_the_operator_api_runs_the_check_where_the_environment_has_pools(
    migrated_db: ScratchDatabase, operator_db: Database
) -> None:
    registry = CollectorRegistry()
    missed = Counter("missed_total", "test", registry=registry)
    directory = FakeDirectory({TOKYO: snapshot()})
    tasks = jobs.start(
        settings_for(migrated_db), operator_db, registry, missed, directory=directory
    )
    try:
        for _ in range(100):
            if registry.get_sample_value("sft_sso_drift_check_last_success_timestamp_seconds"):
                break
            await asyncio.sleep(0.05)
    finally:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
    assert registry.get_sample_value("sft_sso_drift_check_last_success_timestamp_seconds")
