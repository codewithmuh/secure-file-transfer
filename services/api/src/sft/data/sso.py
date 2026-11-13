"""Data access for tenant single sign-on (#231; FR-26; data model 2.1; authn and authz 2.4, 2.5).

- **The tenant's connection** (`idp_connections`, a tenant's row): at most one per tenant. The
  operator API writes it (`put_connection`); the API reads it, in the tenant's scope, and the
  notification worker whether it is active (`active_connection_id`, #273) and whether an
  invitation is an SSO link (`invites_through_sso`).
- **Domains** (`sso_domains`): a tenant claims an email domain with a token it publishes in a DNS
  TXT record, then proves it. A proven domain is the tenant's alone (a unique index), routes
  "Continue with SSO" once an operator links it to the connection, and is a trusted recipient domain
  in the DLP decision (`verified_domains`). Sign-in finds a proven domain's connection through
  `lookup_sso_domain`, in lookup scope (`route_domain`).
- **Group roles** (`sso_group_roles`): which identity provider groups give a member created just
  in time a role.
- **The tenant's SSO settings** (`tenants`): `sso_required`, the MFA confirmation and `sso_jit`.
- **Binding** (`bind_identity`): an SSO subject to a user of the scope's tenant, at sign-in.

Every write runs in the tenant's scope and writes the scope's tenant; the audit trigger requires
the caller's audit event in the same transaction (the service writes it).
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from uuid import UUID

from sqlalchemy import delete, func, insert, select, text, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from sft.core.ids import uuid7
from sft.data.access import in_scope, require_scope, tenant_of
from sft.data.models import (
    IdpConnection,
    Role,
    SsoDomain,
    SsoGroupRole,
    Tenant,
    User,
    UserStatus,
)
from sft.data.scope import ScopeKind
from sft.data.users import UserExistsError, normalize_email

_TENANT = (ScopeKind.TENANT,)


@dataclass(frozen=True, slots=True)
class DomainRoute:
    """Where "Continue with SSO" for a proven domain goes: its tenant's connection."""

    connection_id: UUID
    tenant_id: UUID
    provider_name: str
    status: str


# ---- the connection ----


async def get_connection(session: AsyncSession) -> IdpConnection | None:
    """The scope's tenant's SSO connection, if an operator recorded one."""
    require_scope(session, *_TENANT)
    connection: IdpConnection | None = await session.scalar(
        select(IdpConnection).where(
            IdpConnection.tenant_id.is_not(None), in_scope(IdpConnection, session)
        )
    )
    return connection


async def active_connection_id(session: AsyncSession) -> UUID | None:
    """The scope's tenant's SSO connection, if it is active: its ID. The notification worker's
    test for an SSO invitation (#273): it reads only the ID, tenant and status of the tenant's
    own row (revision 0042), never its issuer."""
    require_scope(session, *_TENANT)
    found: UUID | None = await session.scalar(
        select(IdpConnection.id).where(
            IdpConnection.tenant_id.is_not(None),
            IdpConnection.status == "active",
            in_scope(IdpConnection, session),
        )
    )
    return found


async def invites_through_sso(session: AsyncSession, connection_id: UUID, email: str) -> bool:
    """Whether an invitation to `email` in the scope's tenant is an SSO link (authn and authz 2.5,
    #273): the tenant requires SSO, or the address's domain is one of its proven domains linked to
    `connection_id`, the tenant's active connection. Anyone else may sign in locally, and a link
    to an address outside those domains would be no use: its owner has no identity at the
    tenant's provider. The notification worker's read (revision 0043): `tenants.sso_required` and
    the domains' tenant, name, link and proof, of its own tenant only."""
    require_scope(session, *_TENANT)
    required = await session.scalar(
        select(Tenant.sso_required).where(
            Tenant.id == tenant_of(session), in_scope(Tenant, session)
        )
    )
    if required:
        return True
    domain = email.rpartition("@")[2].lower()
    linked: UUID | None = await session.scalar(
        select(SsoDomain.tenant_id).where(
            SsoDomain.domain == domain,
            SsoDomain.idp_connection_id == connection_id,
            SsoDomain.verified_at.is_not(None),
            in_scope(SsoDomain, session),
        )
    )
    return linked is not None


async def put_connection(
    session: AsyncSession, *, kind: str, provider_name: str, issuer: str, status: str
) -> tuple[IdpConnection, bool]:
    """Create or change the scope's tenant's connection; the row and whether anything changed."""
    require_scope(session, *_TENANT)
    current = await get_connection(session)
    values = {"kind": kind, "provider_name": provider_name, "issuer": issuer, "status": status}
    if current is None:
        created: IdpConnection = (
            await session.scalars(
                insert(IdpConnection)
                .values(id=uuid7(), tenant_id=tenant_of(session), **values)
                .returning(IdpConnection),
                execution_options={"populate_existing": True},
            )
        ).one()
        return created, True
    if all(getattr(current, name) == value for name, value in values.items()):
        return current, False
    changed: IdpConnection = (
        await session.scalars(
            update(IdpConnection)
            .where(IdpConnection.id == current.id, in_scope(IdpConnection, session))
            .values(**values, updated_at=func.now())
            .returning(IdpConnection),
            execution_options={"populate_existing": True},
        )
    ).one()
    return changed, True


# ---- domains ----


async def list_domains(session: AsyncSession) -> Sequence[SsoDomain]:
    require_scope(session, *_TENANT)
    statement = select(SsoDomain).where(in_scope(SsoDomain, session)).order_by(SsoDomain.domain)
    return (await session.scalars(statement)).all()


async def get_domain(
    session: AsyncSession, domain_id: UUID, *, for_update: bool = False
) -> SsoDomain | None:
    require_scope(session, *_TENANT)
    statement = select(SsoDomain).where(SsoDomain.id == domain_id, in_scope(SsoDomain, session))
    if for_update:
        statement = statement.with_for_update().execution_options(populate_existing=True)
    found: SsoDomain | None = await session.scalar(statement)
    return found


async def claim_domain(
    session: AsyncSession, *, domain: str, token: str, created_by: UUID
) -> tuple[SsoDomain, bool]:
    """The tenant's claim of `domain`, new or the one it already has, and whether it is new."""
    require_scope(session, *_TENANT)
    statement = (
        pg_insert(SsoDomain)
        .values(
            id=uuid7(),
            tenant_id=tenant_of(session),
            domain=domain,
            verification_token=token,
            created_by=created_by,
        )
        .on_conflict_do_nothing(index_elements=[SsoDomain.tenant_id, SsoDomain.domain])
        .returning(SsoDomain)
    )
    row: SsoDomain | None = await session.scalar(
        statement, execution_options={"populate_existing": True}
    )
    if row is not None:
        return row, True
    existing: SsoDomain = (
        await session.scalars(
            select(SsoDomain).where(SsoDomain.domain == domain, in_scope(SsoDomain, session))
        )
    ).one()
    return existing, False


async def count_domains(session: AsyncSession) -> int:
    require_scope(session, *_TENANT)
    count = await session.scalar(
        select(func.count()).select_from(SsoDomain).where(in_scope(SsoDomain, session))
    )
    return int(count or 0)


async def mark_verified(session: AsyncSession, domain_id: UUID) -> SsoDomain:
    """Prove the claim. Another tenant's proof of the same domain makes the unique index refuse it
    (`IntegrityError`): the caller runs it in a savepoint."""
    require_scope(session, *_TENANT)
    row: SsoDomain = (
        await session.scalars(
            update(SsoDomain)
            .where(SsoDomain.id == domain_id, in_scope(SsoDomain, session))
            .values(verified_at=func.now(), updated_at=func.now())
            .returning(SsoDomain),
            execution_options={"populate_existing": True},
        )
    ).one()
    return row


async def delete_domain(session: AsyncSession, domain_id: UUID) -> bool:
    require_scope(session, *_TENANT)
    result = await session.execute(
        delete(SsoDomain).where(SsoDomain.id == domain_id, in_scope(SsoDomain, session))
    )
    return bool(result.rowcount)  # type: ignore[attr-defined]


async def link_domains(
    session: AsyncSession, connection_id: UUID, domains: Sequence[str]
) -> tuple[int, int]:
    """Link the tenant's proven `domains` to the connection and unlink its others; how many
    were linked and unlinked by this call."""
    require_scope(session, *_TENANT)
    wanted = list(domains)
    linked = await session.execute(
        update(SsoDomain)
        .where(
            in_scope(SsoDomain, session),
            SsoDomain.domain.in_(wanted),
            SsoDomain.verified_at.is_not(None),
            SsoDomain.idp_connection_id.is_distinct_from(connection_id),
        )
        .values(idp_connection_id=connection_id, updated_at=func.now())
    )
    unlinked = await session.execute(
        update(SsoDomain)
        .where(
            in_scope(SsoDomain, session),
            SsoDomain.domain.not_in(wanted),
            SsoDomain.idp_connection_id.is_not(None),
        )
        .values(idp_connection_id=None, updated_at=func.now())
    )
    return int(linked.rowcount or 0), int(unlinked.rowcount or 0)  # type: ignore[attr-defined]


async def verified_domains(session: AsyncSession) -> tuple[str, ...]:
    """The scope's tenant's proven domains: trusted recipient domains in the DLP decision (FR-45).
    Reads only the columns `sft_scan` and `sft_jobs` may (revision 0029)."""
    require_scope(session, *_TENANT)
    rows = await session.scalars(
        select(SsoDomain.domain).where(
            SsoDomain.verified_at.is_not(None), in_scope(SsoDomain, session)
        )
    )
    return tuple(sorted(rows.all()))


async def route_domain(session: AsyncSession, domain: str) -> DomainRoute | None:
    """The connection a proven, linked domain routes to (data model 4.2), in lookup scope."""
    require_scope(session, ScopeKind.LOOKUP)
    row = (
        await session.execute(
            text(
                "SELECT connection_id, owner_tenant_id, provider_name, status "
                "FROM lookup_sso_domain(:domain)"
            ),
            {"domain": domain},
        )
    ).first()
    return None if row is None else DomainRoute(row[0], row[1], row[2], row[3])


async def connection_domains(session: AsyncSession, connection_id: UUID) -> tuple[str, ...]:
    """The proven domains linked to the connection, in the scope's tenant."""
    require_scope(session, *_TENANT)
    rows = await session.scalars(
        select(SsoDomain.domain).where(
            SsoDomain.idp_connection_id == connection_id,
            SsoDomain.verified_at.is_not(None),
            in_scope(SsoDomain, session),
        )
    )
    return tuple(rows.all())


# ---- group roles ----


async def group_roles(session: AsyncSession) -> Sequence[SsoGroupRole]:
    require_scope(session, *_TENANT)
    statement = (
        select(SsoGroupRole)
        .where(in_scope(SsoGroupRole, session))
        .order_by(SsoGroupRole.group_name)
    )
    return (await session.scalars(statement)).all()


async def replace_group_roles(
    session: AsyncSession, mapping: Sequence[tuple[str, Role]]
) -> tuple[int, int]:
    """Replace the tenant's group roles; how many there were and how many there are."""
    require_scope(session, *_TENANT)
    removed = await session.execute(delete(SsoGroupRole).where(in_scope(SsoGroupRole, session)))
    tenant_id = tenant_of(session)
    if mapping:
        await session.execute(
            insert(SsoGroupRole),
            [
                {"id": uuid7(), "tenant_id": tenant_id, "group_name": group, "role": role.value}
                for group, role in mapping
            ],
        )
    return int(removed.rowcount or 0), len(mapping)  # type: ignore[attr-defined]


# ---- the tenant's settings ----


async def update_tenant_sso(
    session: AsyncSession,
    *,
    sso_required: bool | None = None,
    mfa_confirmed_by: UUID | None = None,
    jit: bool | None = None,
    clear_mfa: bool = False,
) -> Tenant:
    """Change the scope's tenant's SSO columns sent; `mfa_confirmed_by` stamps the confirmation
    with the transaction's time, `clear_mfa` removes it."""
    require_scope(session, *_TENANT)
    values: dict[str, object] = {"updated_at": func.now()}
    if sso_required is not None:
        values["sso_required"] = sso_required
    if jit is not None:
        values["sso_jit"] = jit
    if mfa_confirmed_by is not None:
        values["sso_mfa_confirmed_by"] = mfa_confirmed_by
        values["sso_mfa_confirmed_at"] = func.now()
    elif clear_mfa:
        values["sso_mfa_confirmed_by"] = None
        values["sso_mfa_confirmed_at"] = None
    tenant: Tenant = (
        await session.scalars(
            update(Tenant).where(in_scope(Tenant, session)).values(**values).returning(Tenant),
            execution_options={"populate_existing": True},
        )
    ).one()
    return tenant


# ---- binding ----


async def provision_user(session: AsyncSession, *, email: str, role: Role) -> User:
    """A member created at their first SSO sign-in, active at once (#231): no invitation, no
    outbox message, no pool user. The caller writes `user.provisioned`. Refuses an address that
    is already a user of the tenant (`UserExistsError`), as an invitation does."""
    require_scope(session, *_TENANT)
    statement = (
        pg_insert(User)
        .values(
            id=uuid7(),
            tenant_id=tenant_of(session),
            email=email,
            email_normalized=normalize_email(email),
            role=Role(role).value,
            status=UserStatus.ACTIVE.value,
        )
        .on_conflict_do_nothing(index_elements=[User.tenant_id, User.email_normalized])
        .returning(User)
    )
    user: User | None = await session.scalar(
        statement, execution_options={"populate_existing": True}
    )
    if user is None:
        raise UserExistsError("the address is already a user of this tenant")
    return user


async def bind_identity(
    session: AsyncSession, *, user_id: UUID, connection_id: UUID, subject: str
) -> UUID | None:
    """Bind the provider's `subject` to the user, in the scope's tenant: the new identity's ID, or
    None when the subject is already bound (a sign-in that raced this one)."""
    require_scope(session, *_TENANT)
    identity_id = uuid7()
    inserted = (
        await session.execute(
            text(
                "INSERT INTO user_identities (id, tenant_id, user_id, idp_connection_id, subject) "
                "VALUES (:id, :tenant, :user, :connection, :subject) "
                "ON CONFLICT (idp_connection_id, subject) DO NOTHING RETURNING id"
            ),
            {
                "id": identity_id,
                "tenant": tenant_of(session),
                "user": user_id,
                "connection": connection_id,
                "subject": subject,
            },
        )
    ).first()
    return None if inserted is None else identity_id
