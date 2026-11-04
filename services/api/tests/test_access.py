"""The rules on top of the scope (sft.data.access): who opens which scope, and what it reaches."""

import uuid

import pytest
from sqlalchemy.dialects import postgresql
from sqlalchemy.ext.asyncio import AsyncSession

from sft.data.access import (
    SCOPES_BY_ROLE,
    ScopeNotAllowedError,
    TenantOwned,
    check_scope,
    in_scope,
    require_scope,
    scope_of,
    tenant_of,
)
from sft.data.models import Tenant
from sft.data.roles import API, JOBS, OPERATOR, RELAY, WORKLOAD_ROLES
from sft.data.scope import Scope, ScopeKind, Subject

TENANT = uuid.UUID("0190f5c4-0000-7000-8000-000000000001")
LINK = Subject.recipient(uuid.UUID("0190f5c4-0000-7000-8000-000000000002"))


def session_in(scope: Scope | None, role: str | None = None) -> AsyncSession:
    session = AsyncSession()
    if scope is not None:
        session.info["scope"] = scope
    if role is not None:
        session.info["role"] = role
    return session


def sql(scope: Scope, *, role: str | None = None, write: bool = False) -> str:
    condition = in_scope(Tenant, session_in(scope, role), write=write)
    return str(condition.compile(dialect=postgresql.dialect()))


def test_every_workload_role_has_its_scopes() -> None:
    assert set(SCOPES_BY_ROLE) == set(WORKLOAD_ROLES)
    # Only the API looks up credentials, and only recovery opens the recovery scope.
    assert [r for r, kinds in SCOPES_BY_ROLE.items() if ScopeKind.LOOKUP in kinds] == [API]
    assert [r for r, kinds in SCOPES_BY_ROLE.items() if ScopeKind.RECOVERY in kinds] == [
        "sft_recovery"
    ]


@pytest.mark.parametrize(
    ("role", "scope"),
    [(API, Scope.system()), (RELAY, Scope.tenant(TENANT)), (OPERATOR, Scope.lookup())],
)
def test_a_role_may_not_open_a_scope_it_never_uses(role: str, scope: Scope) -> None:
    with pytest.raises(ScopeNotAllowedError, match="never opens"):
        check_scope(role, scope)


def test_only_workload_roles_open_scopes() -> None:
    with pytest.raises(ScopeNotAllowedError, match="not a workload role"):
        check_scope("postgres", Scope.system())


def test_in_system_scope_only_the_relay_writes_tenant_rows() -> None:
    # Find across, act within: a job changes an item in that item's tenant scope.
    assert sql(Scope.system(), role=JOBS) == "true"
    assert sql(Scope.system(), role=JOBS, write=True) == "false"
    assert sql(Scope.system(), write=True) == "false"
    assert sql(Scope.system(), role=RELAY, write=True) == "true"  # it marks outbox rows sent
    assert sql(Scope.tenant(TENANT), role=JOBS, write=True) == "tenants.id = %(id_1)s::UUID"
    assert sql(Scope.recovery(), role="sft_recovery", write=True) == "true"


def test_a_tenant_scope_filters_by_its_tenant() -> None:
    assert sql(Scope.tenant(TENANT)) == "tenants.id = %(id_1)s::UUID"


def test_a_resource_scope_adds_what_its_subject_reaches() -> None:
    # Tenant.reach is true, which SQLAlchemy folds away: a link session reads its tenant's row.
    assert sql(Scope.resource(TENANT, LINK)) == "tenants.id = %(id_1)s::UUID"


@pytest.mark.parametrize(
    ("scope", "condition"), [(Scope.system(), "true"), (Scope.recovery(), "true")]
)
def test_system_and_recovery_reach_across_tenants(scope: Scope, condition: str) -> None:
    assert sql(scope) == condition


@pytest.mark.parametrize("scope", [Scope.platform(), Scope.lookup()])
def test_platform_and_lookup_scopes_reach_no_tenant_rows(scope: Scope) -> None:
    assert sql(scope) == "false"


def test_a_model_reaches_nothing_in_resource_scope_unless_it_says_so() -> None:
    assert str(TenantOwned.reach(LINK)) == "false"


def test_writes_take_the_tenant_from_the_scope() -> None:
    assert tenant_of(session_in(Scope.resource(TENANT, LINK))) == TENANT
    with pytest.raises(ScopeNotAllowedError, match="a platform scope writes no tenant rows"):
        tenant_of(session_in(Scope.platform()))


def test_a_session_without_a_scope_has_none() -> None:
    with pytest.raises(ScopeNotAllowedError, match="no scope"):
        scope_of(session_in(None))


def test_a_function_of_one_scope_refuses_the_others() -> None:
    assert require_scope(session_in(Scope.lookup()), ScopeKind.LOOKUP) == Scope.lookup()
    with pytest.raises(ScopeNotAllowedError, match="runs in a lookup scope, not tenant"):
        require_scope(session_in(Scope.tenant(TENANT)), ScopeKind.LOOKUP)
