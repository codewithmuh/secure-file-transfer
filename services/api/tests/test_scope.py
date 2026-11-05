import re
import uuid
from pathlib import Path

import pytest

from sft.data.scope import Scope, ScopeKind, Subject, SubjectKind

TENANT = uuid.UUID("0190f5c4-0000-7000-8000-000000000001")
LINK = Subject.recipient(uuid.UUID("0190f5c4-0000-7000-8000-000000000002"))
SOURCE = Path(__file__).resolve().parents[1] / "src"


def test_tenant_and_resource_scopes_carry_their_tenant() -> None:
    assert Scope.tenant(TENANT).settings() == {"scope": "tenant", "tenant_id": str(TENANT)}
    # The subject stays in the data layer: PostgreSQL enforces the tenant boundary only.
    assert Scope.resource(TENANT, LINK).settings() == {
        "scope": "resource",
        "tenant_id": str(TENANT),
    }


def test_a_resource_scope_names_its_subject() -> None:
    scope = Scope.resource(TENANT, Subject.upload_request(LINK.id))
    assert scope.subject == Subject(SubjectKind.UPLOAD_REQUEST, LINK.id)
    with pytest.raises(ValueError, match="needs a subject"):
        Scope(ScopeKind.RESOURCE, TENANT)


@pytest.mark.parametrize("kind", [k for k in ScopeKind if k is not ScopeKind.RESOURCE])
def test_only_a_resource_scope_has_a_subject(kind: ScopeKind) -> None:
    tenant = TENANT if kind is ScopeKind.TENANT else None
    with pytest.raises(ValueError, match="has no subject"):
        Scope(kind, tenant, LINK)


def test_a_subject_is_typed() -> None:
    with pytest.raises(TypeError, match="Subject"):
        Scope(ScopeKind.RESOURCE, TENANT, "recipient")  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="SubjectKind"):
        Subject("recipient", LINK.id)  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="UUID"):
        Subject.recipient(str(LINK.id))  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("scope", "kind"),
    [
        (Scope.system(), "system"),
        (Scope.platform(), "platform"),
        (Scope.lookup(), "lookup"),
        (Scope.recovery(), "recovery"),
    ],
)
def test_other_scopes_set_no_tenant(scope: Scope, kind: str) -> None:
    # An empty app.tenant_id reads as null in app_tenant_id(), and null equals no tenant_id.
    assert scope.settings() == {"scope": kind, "tenant_id": ""}


@pytest.mark.parametrize("kind", [ScopeKind.TENANT, ScopeKind.RESOURCE])
def test_a_tenant_scope_needs_a_tenant(kind: ScopeKind) -> None:
    with pytest.raises(ValueError, match="needs a tenant"):
        Scope(kind, subject=LINK)


@pytest.mark.parametrize(
    "kind", [ScopeKind.SYSTEM, ScopeKind.PLATFORM, ScopeKind.LOOKUP, ScopeKind.RECOVERY]
)
def test_other_scopes_refuse_a_tenant(kind: ScopeKind) -> None:
    with pytest.raises(ValueError, match="has no tenant"):
        Scope(kind, TENANT)


def test_a_tenant_must_be_a_uuid_not_text() -> None:
    with pytest.raises(TypeError, match="UUID"):
        Scope.tenant(str(TENANT))  # type: ignore[arg-type]


def test_the_kind_must_be_a_scope_kind() -> None:
    with pytest.raises(TypeError, match="ScopeKind"):
        Scope("tenant", TENANT)  # type: ignore[arg-type]


def test_scopes_are_immutable() -> None:
    scope = Scope.tenant(TENANT)
    with pytest.raises(AttributeError):
        scope.tenant_id = uuid.uuid4()  # type: ignore[misc]


# The lint rule of ADR-0020: the scope is set for one transaction, never for the session.
SESSION_LEVEL = [
    re.compile(r"set_config\(\s*'app\.[a-z_]+'\s*,[^)]*,\s*false\s*\)", re.IGNORECASE),
    re.compile(r"\bSET\s+(SESSION\s+)?app\.", re.IGNORECASE),
    re.compile(r"\bRESET\s+app\.", re.IGNORECASE),
]


def test_no_code_sets_the_scope_for_a_session() -> None:
    offenders = [
        f"{path.relative_to(SOURCE)}: {pattern.pattern}"
        for path in SOURCE.rglob("*.py")
        for pattern in SESSION_LEVEL
        if pattern.search(path.read_text())
    ]
    assert offenders == []


@pytest.mark.parametrize(
    "line",
    [
        "SELECT set_config('app.tenant_id', :t, false)",
        "SET app.tenant_id = '1'",
        "set session app.scope to 'system'",
        "RESET app.scope",
    ],
)
def test_the_lint_rule_catches_session_settings(line: str) -> None:
    assert any(pattern.search(line) for pattern in SESSION_LEVEL)


def test_the_lint_rule_allows_transaction_settings() -> None:
    line = "SELECT set_config('app.scope', :scope, true), set_config('app.tenant_id', :t, true)"
    assert not any(pattern.search(line) for pattern in SESSION_LEVEL)
