"""The permission registry against the contract and table 6.3, and `authorize` rule by rule
(authn and authz 6.3, 6.5, 9.2 "Declared permissions")."""

from __future__ import annotations

import re
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from fastapi.routing import APIRoute, iter_route_contexts

from sft.api.app import create_app
from sft.core.errors import Forbidden, ProblemError, Unauthenticated
from sft.data.models import ActorType, Role
from sft.data.scope import Subject
from sft.service.caller import AuthMethod, Caller, CallerKind
from sft.service.permissions import (
    BY_OPERATION,
    PASSKEY_EXEMPT,
    REGISTRY,
    STEP_UP,
    Permission,
    Reach,
    _by_operation,
    authorize,
    permission_for,
)
from sft.service.rate_limits.limits import KeyType
from test_authorization_matrix import API_KEY_SCOPES
from tools.contract_check import CONTRACT, METHODS, load_contract

DOCS = Path(__file__).resolve().parents[3] / "docs"
NOW = datetime(2026, 11, 4, 12, 0, tzinfo=UTC)


def contract_permissions() -> dict[str, str]:
    contract = load_contract(CONTRACT)
    return {
        operation["operationId"]: operation["x-permission"]
        for path_item in contract["paths"].values()
        for method, operation in path_item.items()
        if method in METHODS
    }


def test_every_contract_operation_declares_a_permission_the_registry_holds() -> None:
    declared = contract_permissions()
    registered = {op: permission.name for op, permission in BY_OPERATION.items()}
    assert declared == registered


def test_the_registry_is_table_6_3() -> None:
    # Table 6.3 of the authentication and authorization design, parsed row by row.
    text = (DOCS / "security" / "authn-authz.md").read_text()
    table = text.split("### 6.3 Permission table")[1].split("### 6.4")[0]
    rows = [line for line in table.splitlines() if line.startswith("| `")]
    assert len(rows) == len(REGISTRY)
    for line, permission in zip(rows, REGISTRY, strict=True):
        cells = [cell.strip() for cell in line.strip("|").split("|")]
        assert cells[0] == f"`{permission.name}`"
        assert tuple(re.findall(r"`([A-Za-z]+)`", cells[1])) == permission.operations
        if permission.public:
            continue
        member, admin, key, recipient, uploader, operator = cells[2:8]
        assert _reach(member) is permission.member, permission.name
        assert _reach(admin) is permission.admin, permission.name
        if key.startswith("—"):
            assert permission.api_key is None, permission.name
        else:
            assert permission.api_key == tuple(re.findall(r"`([a-z_]+:[a-z]+)`", key))
        assert (not recipient.startswith("—")) is permission.recipient, permission.name
        assert (not uploader.startswith("—")) is permission.uploader, permission.name
        assert (not operator.startswith("—")) is permission.operator, permission.name


def _reach(cell: str) -> Reach:
    for prefix, reach in (
        ("—", Reach.NONE),
        ("Self", Reach.SELF),
        ("Yes", Reach.ANY),
        ("Own", Reach.OWN),
        ("Tenant", Reach.TENANT),
        ("Approvers only", Reach.APPROVER),
    ):
        if cell.startswith(prefix):
            return reach
    raise AssertionError(f"unknown cell {cell!r}")


def test_step_up_and_the_passkey_exemptions_name_real_operations() -> None:
    assert set(BY_OPERATION) >= STEP_UP
    assert set(BY_OPERATION) >= PASSKEY_EXEMPT
    # The contract's own list of step-up operations (memberSession, "Step-up").
    contract = CONTRACT.read_text()
    listed = contract.split("- **Step-up.**")[1].split("need a sign-in")[0]
    assert set(re.findall(r"`([A-Za-z]+)`", listed)) <= STEP_UP


def test_every_route_of_the_app_is_a_registered_operation() -> None:
    routes = [c.original_route for c in iter_route_contexts(create_app().routes)]
    assert routes
    for route in routes:
        assert isinstance(route, APIRoute)
        assert route.operation_id in BY_OPERATION, route.path


def test_an_operation_belongs_to_one_permission() -> None:
    with pytest.raises(ValueError, match="getUser"):
        _by_operation((Permission("a", ("getUser",)), Permission("b", ("getUser",))))
    with pytest.raises(KeyError):
        permission_for("noSuchOperation")


# ---- authorize ----


def member(role: Role, method: AuthMethod = AuthMethod.PASSKEY, **changes: object) -> Caller:
    caller = Caller.member(
        tenant_id=uuid.uuid4(),
        user_id=uuid.uuid4(),
        role=role,
        auth_method=method,
        auth_time=NOW - timedelta(minutes=1),
        session_id=uuid.uuid4(),
    )
    return Caller(**{**{f: getattr(caller, f) for f in caller.__slots__}, **changes})  # type: ignore[arg-type]


ADMIN = member(Role.ADMIN)
MEMBER = member(Role.MEMBER)


@contextmanager
def refused(kind: type[ProblemError], code: str) -> Iterator[None]:
    """The block raises `kind` with `code`, the contract's problem code."""
    with pytest.raises(kind) as caught:
        yield
    assert caught.value.code == code


def test_public_operations_admit_anyone() -> None:
    assert authorize(None, "startSignIn", now=NOW) is Reach.ANY


def test_no_credential_is_401() -> None:
    with refused(Unauthenticated, "authentication_required"):
        authorize(None, "listUsers", now=NOW)


def test_an_admin_with_a_passkey_reaches_the_tenant() -> None:
    assert authorize(ADMIN, "listUsers", now=NOW) is Reach.TENANT
    assert authorize(ADMIN, "listTransfers", now=NOW) is Reach.TENANT


def test_a_member_is_refused_admin_operations_and_reaches_their_own_items() -> None:
    with refused(Forbidden, "permission_denied"):
        authorize(MEMBER, "listUsers", now=NOW)
    assert authorize(MEMBER, "listTransfers", now=NOW) is Reach.OWN
    assert authorize(MEMBER, "getCurrentMember", now=NOW) is Reach.SELF


@pytest.mark.parametrize("method", [AuthMethod.PASSWORD_TOTP, AuthMethod.LOCAL])
def test_a_local_admin_without_a_passkey_acts_as_a_member(method: AuthMethod) -> None:
    admin = member(Role.ADMIN, method)
    with refused(Forbidden, "passkey_required"):
        authorize(admin, "listUsers", now=NOW)
    assert authorize(admin, "listTransfers", now=NOW) is Reach.OWN
    # Revocations are exempt: they only stop sharing (3.3).
    assert authorize(admin, "revokeTransfer", now=NOW) is Reach.TENANT


def test_an_sso_admin_and_the_rule_turned_off_act_as_admins() -> None:
    assert authorize(member(Role.ADMIN, AuthMethod.SSO), "listUsers", now=NOW) is Reach.TENANT
    off = member(Role.ADMIN, AuthMethod.PASSWORD_TOTP, passkey_rule=False)
    assert authorize(off, "listUsers", now=NOW) is Reach.TENANT


def test_step_up_operations_need_a_recent_sign_in() -> None:
    stale = member(Role.ADMIN, auth_time=NOW - timedelta(minutes=16))
    with refused(Unauthenticated, "reauthentication_required"):
        authorize(stale, "inviteUser", now=NOW)
    assert authorize(stale, "listUsers", now=NOW) is Reach.TENANT
    unknown = member(Role.ADMIN, auth_time=None)
    with refused(Unauthenticated, "reauthentication_required"):
        authorize(unknown, "deactivateUser", now=NOW)


def test_api_keys_need_one_of_the_scopes() -> None:
    key = Caller(CallerKind.API_KEY, tenant_id=uuid.uuid4(), credential_id=uuid.uuid4())
    with refused(Unauthenticated, "authentication_required"):
        authorize(key, "createTenant", now=NOW)  # no credential the operation accepts
    with refused(Forbidden, "permission_denied"):
        authorize(key, "listTransfers", now=NOW)


def test_api_keys_are_refused_with_403_on_every_operation_for_web_sessions_only() -> None:
    # A key is a credential the member routes read (#215), so its refusal there is 403 (T-55).
    key = Caller(
        CallerKind.API_KEY,
        tenant_id=uuid.uuid4(),
        user_id=uuid.uuid4(),
        credential_id=uuid.uuid4(),
        scopes=frozenset(API_KEY_SCOPES),
    )
    web_only = [
        operation
        for permission in REGISTRY
        if permission.api_key is None
        and (permission.member, permission.admin) != (Reach.NONE, Reach.NONE)
        for operation in permission.operations
    ]
    assert {"listUsers", "createApiKey", "revokeApiKey", "clearEmailSuppression"} <= set(web_only)
    assert {"getCurrentMember", "unlockRecipient", "createReceivedFileDownload"} <= set(web_only)
    for operation in web_only:
        with refused(Forbidden, "permission_denied"):
            authorize(key, operation, now=NOW)
    reader = Caller(CallerKind.API_KEY, scopes=frozenset({"transfers:read"}))
    assert authorize(reader, "listTransfers", now=NOW) is Reach.TENANT
    writer = Caller(CallerKind.API_KEY, scopes=frozenset({"transfers:write"}))
    assert authorize(writer, "sendTransfer", now=NOW) is Reach.OWN


def test_link_sessions_reach_their_own_subject_only() -> None:
    recipient = Caller(CallerKind.RECIPIENT, subject=Subject.recipient(uuid.uuid4()))
    uploader = Caller(CallerKind.UPLOADER, subject=Subject.upload_request(uuid.uuid4()))
    assert authorize(recipient, "createSessionDownload", now=NOW) is Reach.OWN
    assert authorize(uploader, "addSessionUploadFile", now=NOW) is Reach.OWN
    with refused(Forbidden, "permission_denied"):
        authorize(uploader, "createSessionDownload", now=NOW)
    with refused(Forbidden, "permission_denied"):
        authorize(recipient, "addSessionUploadFile", now=NOW)
    with refused(Unauthenticated, "authentication_required"):
        authorize(recipient, "listUsers", now=NOW)


def test_operators_and_system_actors() -> None:
    operator = Caller(CallerKind.OPERATOR, credential_id=uuid.uuid4())
    assert authorize(operator, "createTenant", now=NOW) is Reach.ANY
    with refused(Unauthenticated, "authentication_required"):
        authorize(operator, "listUsers", now=NOW)
    assert authorize(Caller(CallerKind.SYSTEM), "listUsers", now=NOW) is Reach.TENANT


def test_a_401_to_a_bearer_credential_carries_the_challenge() -> None:
    for kind, operation in (
        (CallerKind.API_KEY, "createTenant"),
        (CallerKind.OPERATOR, "listUsers"),
    ):
        with pytest.raises(Unauthenticated) as caught:
            authorize(Caller(kind, credential_id=uuid.uuid4()), operation, now=NOW)
        assert caught.value.bearer
    with pytest.raises(Unauthenticated) as cookie:
        authorize(None, "listUsers", now=NOW)
    assert not cookie.value.bearer


def test_the_rate_limit_keys_follow_the_caller() -> None:
    tenant, user, credential = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
    session = Caller(CallerKind.MEMBER, tenant_id=tenant, user_id=user, credential_id=credential)
    assert session.rate_limit_keys() == {KeyType.ACCOUNT: str(user), KeyType.TENANT: str(tenant)}
    key = Caller(CallerKind.API_KEY, tenant_id=tenant, user_id=user, credential_id=credential)
    assert key.rate_limit_keys() == {KeyType.API_KEY: str(credential), KeyType.TENANT: str(tenant)}
    operator = Caller(CallerKind.OPERATOR, credential_id=credential)
    assert operator.rate_limit_keys() == {KeyType.OPERATOR: str(credential)}
    # A link session never counts against its tenant's budget (abuse and rate limits 2.2, H).
    recipient = Caller(CallerKind.RECIPIENT, tenant_id=tenant, credential_id=credential)
    assert recipient.rate_limit_keys() == {KeyType.LINK_SESSION: str(credential)}
    assert Caller(CallerKind.SYSTEM).rate_limit_keys() == {}


def test_the_audit_actor_follows_the_caller() -> None:
    assert ADMIN.actor().type is ActorType.ADMIN
    assert member(Role.ADMIN, AuthMethod.PASSWORD_TOTP).actor().type is ActorType.MEMBER
    assert MEMBER.actor().id == MEMBER.user_id
    subject = Subject.recipient(uuid.uuid4())
    assert Caller(CallerKind.RECIPIENT, subject=subject).actor().id == subject.id
    key = Caller(CallerKind.API_KEY, credential_id=uuid.uuid4())
    assert (key.actor().type, key.actor().id) == (ActorType.API_KEY, key.credential_id)
    assert Caller(CallerKind.SYSTEM).actor().id is None
    with pytest.raises(TypeError):
        Caller("member")  # type: ignore[arg-type]
