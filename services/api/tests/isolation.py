"""The two-tenant isolation harness (NFR-12; data model 4.2, point 5; authn and authz 9.2).

Every data-access function, and later every endpoint, gets a case. A case calls the function in
one tenant's scope ("mine") with the other tenant's IDs ("theirs"). The harness runs it in every
scope the case names and in the tenant-less scopes its role may open, three ways:

- `AS_BUILT`: the data-access layer and row-level security together;
- `DATA_LAYER_ALONE`: row-level security disabled on every table, so `in_scope` must hold;
- `RLS_ALONE`: `in_scope`'s tenant filter removed, so the policies must hold.

After each attempt it fails the build if the result carries anything of theirs (an ID or the
marker written into their rows), if any of their rows changed, or if any row of another tenant
now refers to one of their IDs. Refusals are fine: no row, a policy or privilege error, a
foreign key violation, or the data layer's own `NotFoundError` or `ScopeNotAllowedError`. Any
other exception, a `KeyError` included, fails the case.

Adding a case (README, "The isolation suite"):

    cases = Cases()

    @cases.add(scopes={API: [TENANT, RESOURCE], OPERATOR: [TENANT]})
    async def get_another_tenants_tenant(session: AsyncSession, tenants: Tenants) -> object:
        return await get_tenant(session, tenants.theirs.tenant_id)

    test_isolation = cases.test()

A new table also gets its rows in `seed_tenant`, so every case has something of theirs to miss.
"""

from __future__ import annotations

import secrets
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable, Iterator, Mapping, Sequence
from contextlib import AsyncExitStack, asynccontextmanager, contextmanager, nullcontext
from dataclasses import dataclass, field
from enum import StrEnum
from unittest import mock

import pytest
from sqlalchemy import URL, create_engine, inspect, text, true
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import DeclarativeBase

import isolation_fixture
from pg import TENANT_TABLES, ScratchDatabase, Sql, fresh_database
from sft.data import access
from sft.data.access import SCOPES_BY_ROLE, NotFoundError, ScopeNotAllowedError
from sft.data.database import Database, psycopg_url
from sft.data.migrate import run
from sft.data.roles import MIGRATE, OPERATOR
from sft.data.scope import Scope, ScopeKind, Subject


class Mode(StrEnum):
    AS_BUILT = "as_built"
    DATA_LAYER_ALONE = "data_layer_alone"
    RLS_ALONE = "rls_alone"


MODES = tuple(Mode)

# What a refusal looks like from PostgreSQL: a policy or a grant (42501), a foreign key (23503).
# Anything else is a bug, and the case fails with it.
REFUSED = frozenset({"42501", "23503"})

# Scopes that read across tenants by design, when a case names them: a job's find step in system
# scope, a credential lookup in lookup scope. There the harness checks that nothing changed, not
# what was read; the lookup's own tests check it returns IDs and status only. Recovery re-applies
# records across tenants and has its own policy tests, so no case runs in it.
_ACROSS = frozenset({ScopeKind.SYSTEM, ScopeKind.LOOKUP})
# The operator API's tenant directory (#111): `sft_operator` reads tenant rows in platform scope, by
# design, when a case says so with `across=`. No other role or scope may be named there.
_ACROSS_ON_REQUEST = {ScopeKind.PLATFORM: frozenset({OPERATOR})}
_TENANTLESS = (ScopeKind.PLATFORM, ScopeKind.LOOKUP)


@dataclass(frozen=True)
class Seeded:
    """One tenant's rows: its ID, the marker in its text columns, and its other rows by name."""

    tenant_id: uuid.UUID
    marker: str
    rows: Mapping[str, uuid.UUID] = field(default_factory=dict)

    def ids(self) -> set[uuid.UUID]:
        return {self.tenant_id, *self.rows.values()}


@dataclass(frozen=True)
class Tenants:
    mine: Seeded
    theirs: Seeded


Call = Callable[[AsyncSession, Tenants], Awaitable[object]]


@dataclass(frozen=True)
class Case:
    name: str
    call: Call
    scopes: Mapping[str, Sequence[ScopeKind]]
    """For each workload role, the scopes the function is used in."""
    subject: Callable[[Seeded], Subject] | None = None
    """Mine's subject in resource scope; by default one that reaches nothing below the tenant."""
    across: frozenset[ScopeKind] = frozenset()
    """Named scopes this case reads across tenants in by design: the operator's directory."""

    def __str__(self) -> str:
        return self.name

    def attempts(self) -> list[tuple[str, ScopeKind, bool]]:
        """Each (role, scope, named): the scopes named, then the tenant-less ones the role opens."""
        tried = []
        for kind in self.across:
            allowed_roles = _ACROSS_ON_REQUEST.get(kind, frozenset())
            naming = {role for role, kinds in self.scopes.items() if kind in kinds}
            if not naming <= allowed_roles:
                raise ValueError(f"{self.name}: only {sorted(allowed_roles)} read across in {kind}")
        for role, kinds in self.scopes.items():
            allowed = SCOPES_BY_ROLE[role]
            for kind in kinds:
                if kind not in allowed:
                    raise ValueError(f"{self.name}: {role} never opens a {kind} scope")
                if kind is ScopeKind.RECOVERY:
                    raise ValueError(f"{self.name}: recovery reaches across tenants by design")
            tried += [(role, kind, True) for kind in kinds]
            tried += [(role, k, False) for k in _TENANTLESS if k in allowed and k not in kinds]
        return tried


class Cases:
    """A module's isolation cases, and the test that runs them."""

    def __init__(self) -> None:
        self._cases: list[Case] = []

    def add(
        self,
        *,
        scopes: Mapping[str, Sequence[ScopeKind]],
        subject: Callable[[Seeded], Subject] | None = None,
        across: Sequence[ScopeKind] = (),
    ) -> Callable[[Call], Call]:
        def register(call: Call) -> Call:
            self._cases.append(Case(call.__name__, call, scopes, subject, frozenset(across)))
            return call

        return register

    def __iter__(self) -> Iterator[Case]:
        return iter(self._cases)

    def test(self) -> Callable[..., Awaitable[None]]:
        """The test function: every case, in every mode. Assign it to a `test_…` name."""

        @pytest.mark.anyio
        @pytest.mark.parametrize("mode", MODES)
        @pytest.mark.parametrize("case", list(self._cases), ids=str)
        async def test_no_tenant_reaches_another(
            case: Case, mode: Mode, isolation_world: World
        ) -> None:
            await isolation_world.check(case, mode)

        return test_no_tenant_reaches_another


# ---- the databases ----


@contextmanager
def world_database(admin_url: URL, *, rls: bool) -> Iterator[ScratchDatabase]:
    """A migrated database with the stand-in tables; with `rls=False`, row-level security off."""
    with fresh_database(admin_url) as db:
        run(db.url(MIGRATE))
        db.as_owner(isolation_fixture.create)
        if not rls:
            for (table,) in db.sql(
                "SELECT relname FROM pg_class WHERE relnamespace = 'public'::regnamespace "
                "AND relrowsecurity"
            ):
                db.sql(f'ALTER TABLE "{table}" DISABLE ROW LEVEL SECURITY')
        yield db


class Admin:
    """The superuser on one database, over one pooled connection the checks share."""

    def __init__(self, db: ScratchDatabase) -> None:
        self._engine = create_engine(psycopg_url(db.admin), pool_size=1, max_overflow=0)
        self._tables: list[str] | None = None
        self._uuid_columns: list[tuple[str, str]] | None = None

    def sql(self, statement: str, **params: object) -> list[tuple[object, ...]]:
        with self._engine.begin() as connection:
            result = connection.execute(text(statement), params)
            return [tuple(row) for row in result] if result.returns_rows else []

    def dispose(self) -> None:
        self._engine.dispose()

    def tenant_tables(self) -> list[str]:
        """Read from the catalog once per world: its schema doesn't change while it runs."""
        if self._tables is None:
            self._tables = sorted(str(name) for (name,) in self.sql(TENANT_TABLES))
        return self._tables

    def uuid_columns(self) -> list[tuple[str, str]]:
        """The uuid columns of tenant tables, other than their own ID and tenant."""
        if self._uuid_columns is None:
            owned = set(self.tenant_tables()) - {"tenants"}
            rows = self.sql(
                """
                SELECT c.relname, a.attname FROM pg_class c
                  JOIN pg_attribute a ON a.attrelid = c.oid
                 WHERE c.relnamespace = 'public'::regnamespace AND c.relkind IN ('r', 'p')
                   AND NOT c.relispartition AND a.attnum > 0 AND NOT a.attisdropped
                   AND a.atttypid = 'uuid'::regtype AND a.attname NOT IN ('id', 'tenant_id')
                 ORDER BY 1, 2
                """
            )
            self._uuid_columns = [(str(t), str(c)) for t, c in rows if t in owned]
        return self._uuid_columns


def seed_tenant(db: Sql, label: str) -> Seeded:
    """One tenant and a row in every tenant table, as the superuser.

    The superuser path skips the policies and the audit trigger of #50, so seeding is never
    mistaken for the code under test. A migration that adds a tenant table adds its rows here.
    """
    tenant_id = uuid.uuid4()
    marker = f"isolation-{label}-{secrets.token_hex(4)}"
    db.sql(
        "INSERT INTO tenants (id, name, status) VALUES (:id, :name, 'active')",
        id=tenant_id,
        name=marker,
    )
    rows = isolation_fixture.seed(db, tenant_id, marker)
    # The outbox (#51): one unpublished message, and one message a consumer has recorded.
    rows["outbox"], rows["processed_message"] = uuid.uuid4(), uuid.uuid4()
    db.sql(
        "INSERT INTO outbox (id, tenant_id, topic, payload, last_error) VALUES (:id, :tenant, "
        "'isolation.seed', jsonb_build_object('file_id', CAST(:file AS text)), :marker)",
        id=rows["outbox"],
        tenant=tenant_id,
        file=str(rows["outbox"]),
        marker=marker,
    )
    db.sql(
        "INSERT INTO processed_messages (consumer, message_id, tenant_id) "
        "VALUES ('isolation', :message, :tenant)",
        message=str(rows["processed_message"]),
        tenant=tenant_id,
    )
    # Users (#112): an invited member with a live invitation link, whose address holds the marker.
    rows["user"], rows["invitation"] = uuid.uuid4(), uuid.uuid4()
    db.sql(
        "INSERT INTO users (id, tenant_id, email, email_normalized, role, status, "
        "invitation_token_hash, invitation_expires_at) VALUES (:id, :tenant, :email, :email, "
        "'member', 'invited', sha256(convert_to(:token, 'UTF8')), now() + interval '7 days')",
        id=rows["user"],
        tenant=tenant_id,
        email=f"{marker}@example.test",
        token=str(rows["invitation"]),
    )
    # The tenant's policy and recovery contact (#111), the contact holding the marker.
    db.sql(
        "UPDATE tenants SET recovery_contact = :marker WHERE id = :tenant",
        marker=marker,
        tenant=tenant_id,
    )
    db.sql(
        "INSERT INTO tenant_policies (tenant_id, default_locale) VALUES (:tenant, 'ja')",
        tenant=tenant_id,
    )
    # Member sign-in (#113): the tenant's own SSO connection, named with the marker, the user's
    # identity there, and a live session, whose token is the SHA-256 of the session's row name.
    rows["connection"], rows["identity"], rows["session"] = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
    rows["session_token"] = uuid.uuid4()
    db.sql(
        "INSERT INTO idp_connections (id, tenant_id, kind, provider_name, issuer, status) "
        "VALUES (:id, :tenant, 'oidc', :marker, :marker, 'active')",
        id=rows["connection"],
        tenant=tenant_id,
        marker=marker,
    )
    db.sql(
        "INSERT INTO user_identities (id, tenant_id, user_id, idp_connection_id, subject) "
        "VALUES (:id, :tenant, :user, :connection, :marker)",
        id=rows["identity"],
        tenant=tenant_id,
        user=rows["user"],
        connection=rows["connection"],
        marker=marker,
    )
    db.sql(
        "INSERT INTO member_sessions (id, tenant_id, user_id, identity_id, session_hash, "
        "auth_time, auth_method, expires_at, user_agent) VALUES (:id, :tenant, :user, :identity, "
        "sha256(convert_to(:token, 'UTF8')), now(), 'sso', now() + interval '12 hours', :marker)",
        id=rows["session"],
        tenant=tenant_id,
        user=rows["user"],
        identity=rows["identity"],
        token=str(rows["session_token"]),
        marker=marker,
    )
    # Idempotency keys (#144): the user's live key, named with the marker, and an expired one.
    for key, expires in ((marker, "1 day"), (f"{marker}-old", "-1 day")):
        db.sql(
            "INSERT INTO idempotency_keys (tenant_id, caller_type, caller_id, key, "
            "request_fingerprint, response_status, resource_type, resource_id, created_at, "
            "expires_at) VALUES (:tenant, 'member', :user, :key, sha256(convert_to(:key, 'UTF8')), "
            "201, 'user', :user, now() - interval '2 days', now() + CAST(:expires AS interval))",
            tenant=tenant_id,
            user=rows["user"],
            key=key,
            expires=expires,
        )
    seed_transfers(db, tenant_id, marker, rows)
    # API keys (#215): a live key of the user, named with the marker, whose token is the key's
    # row name; it expires within 14 days, so the daily job's find step sees it.
    rows["api_key"], rows["api_key_token"] = uuid.uuid4(), uuid.uuid4()
    db.sql(
        "INSERT INTO api_keys (id, tenant_id, created_by, name, key_prefix, key_hash, scopes, "
        "expires_at) VALUES (:id, :tenant, :user, :marker, 'sft_dev_Isolatn0', "
        "sha256(convert_to(:token, 'UTF8')), ARRAY['transfers:read', 'audit:read'], "
        "now() + interval '10 days')",
        id=rows["api_key"],
        tenant=tenant_id,
        user=rows["user"],
        marker=marker,
        token=str(rows["api_key_token"]),
    )
    seed_dlp(db, tenant_id, marker, rows)
    seed_dlp_decisions(db, tenant_id, marker, rows)
    seed_dlp_approvals(db, tenant_id, marker, rows)
    seed_notice_windows(db, tenant_id, rows)
    seed_dlp_should(db, tenant_id, rows)
    seed_data_keys(db, tenant_id, marker)
    seed_sso(db, tenant_id, marker, rows)
    return Seeded(tenant_id, marker, rows)


def seed_sso(db: Sql, tenant_id: uuid.UUID, marker: str, rows: dict[str, uuid.UUID]) -> None:
    """Tenant SSO (#231, revision 0029): a proven domain named with the marker, linked to the
    tenant's connection, a pending claim, and a group role named with the marker."""
    for key in ("sso_domain", "sso_domain_pending", "sso_group_role"):
        rows[key] = uuid.uuid4()
    db.sql(
        "INSERT INTO sso_domains (id, tenant_id, domain, verification_token, verified_at, "
        "idp_connection_id, created_by) VALUES (:id, :tenant, :domain, repeat('i', 32), now(), "
        ":connection, :user)",
        id=rows["sso_domain"],
        tenant=tenant_id,
        domain=f"{marker}.example",
        connection=rows["connection"],
        user=rows["user"],
    )
    db.sql(
        "INSERT INTO sso_domains (id, tenant_id, domain, verification_token, created_by) "
        "VALUES (:id, :tenant, :domain, repeat('p', 32), :user)",
        id=rows["sso_domain_pending"],
        tenant=tenant_id,
        domain=f"pending-{marker}.example",
        user=rows["user"],
    )
    db.sql(
        "INSERT INTO sso_group_roles (id, tenant_id, group_name, role) "
        "VALUES (:id, :tenant, :marker, 'admin')",
        id=rows["sso_group_role"],
        tenant=tenant_id,
        marker=marker,
    )


def seed_transfers(db: Sql, tenant_id: uuid.UUID, marker: str, rows: dict[str, uuid.UUID]) -> None:
    """Transfers (#114): a draft of the seeded user, its recipient, an uploading file, a file that
    is completing, and the tenant's storage reservation. The marker is in the address, the sealed
    name and the upload ID."""
    for key in ("transfer", "recipient", "file", "completing_file"):
        rows[key] = uuid.uuid4()
    db.sql(
        # The member asked for the first-download notice, so a case can try to claim it (#214).
        "INSERT INTO transfers (id, tenant_id, created_by, state, expires_in, message_ct, "
        "notify_on_first_download) VALUES (:id, :tenant, :user, 'draft', interval '7 days', "
        "convert_to(:marker, 'UTF8'), true)",
        id=rows["transfer"],
        tenant=tenant_id,
        user=rows["user"],
        marker=marker,
    )
    db.sql(
        "INSERT INTO transfer_recipients (id, tenant_id, transfer_id, email, email_normalized, "
        "locale) VALUES (:id, :tenant, :transfer, :email, :email, 'en')",
        id=rows["recipient"],
        tenant=tenant_id,
        transfer=rows["transfer"],
        email=f"{marker}@recipient.test",
    )
    for key, state in (("file", "uploading"), ("completing_file", "completing")):
        db.sql(
            "INSERT INTO files (id, tenant_id, transfer_id, display_name_ct, content_type, "
            "declared_size, storage_class, storage_key, s3_upload_id, part_size, part_count, "
            "state, completion_started_at) VALUES (:id, :tenant, :transfer, "
            "convert_to(:marker, 'UTF8'), 'text/plain', 10, 'standard', "
            "'tenants/' || :tenant || '/files/' || :id, :marker, 5242880, 1, :state, "
            "CASE WHEN :state = 'completing' THEN now() END)",
            id=rows[key],
            tenant=tenant_id,
            transfer=rows["transfer"],
            marker=marker,
            state=state,
        )
    db.sql(
        "INSERT INTO tenant_usage (tenant_id, bytes_reserved) VALUES (:tenant, 20)",
        tenant=tenant_id,
    )
    seed_scans(db, tenant_id, marker, rows)


def seed_scans(db: Sql, tenant_id: uuid.UUID, marker: str, rows: dict[str, uuid.UUID]) -> None:
    """Sending and scanning (#174 to #176): a file past its scan deadline, its finding, a download
    counter for the recipient, and a suppressed address whose pseudonym holds the marker."""
    for key in ("scanning_file", "finding", "suppression"):
        rows[key] = uuid.uuid4()
    db.sql(
        "INSERT INTO files (id, tenant_id, transfer_id, display_name_ct, content_type, "
        "declared_size, actual_size, storage_class, storage_key, s3_upload_id, s3_version_id, "
        "part_size, part_count, state, scan_deadline) VALUES (:id, :tenant, :transfer, "
        "convert_to(:marker, 'UTF8'), 'text/plain', 10, 10, 'standard', "
        "'tenants/' || :tenant || '/files/' || :id, :marker, :marker, 5242880, 1, 'scanning', "
        "now() - interval '1 minute')",
        id=rows["scanning_file"],
        tenant=tenant_id,
        transfer=rows["transfer"],
        marker=marker,
    )
    db.sql(
        "INSERT INTO dlp_findings (id, tenant_id, file_id, detector, count_low, count_medium, "
        "count_high) VALUES (:id, :tenant, :file, 'jp_my_number', 0, 0, 1)",
        id=rows["finding"],
        tenant=tenant_id,
        file=rows["scanning_file"],
    )
    db.sql(
        "INSERT INTO download_counters (tenant_id, recipient_id, file_id) "
        "VALUES (:tenant, :recipient, :file)",
        tenant=tenant_id,
        recipient=rows["recipient"],
        file=rows["scanning_file"],
    )
    db.sql(
        "INSERT INTO email_suppressions (id, tenant_id, email_hmac, hmac_key_id, reason) "
        "VALUES (:id, :tenant, 'eiso:' || :marker, 'iso', 'complaint')",
        id=rows["suppression"],
        tenant=tenant_id,
        marker=marker,
    )
    seed_links(db, tenant_id, rows)


def seed_links(db: Sql, tenant_id: uuid.UUID, rows: dict[str, uuid.UUID]) -> None:
    """Links and verification (#178, #179): the recipient's link, whose token is the text of
    `link_token`, a live code, and a live link session, whose token is the text of
    `link_session_token`; and that session's download grants (#180)."""
    for key in ("link_token", "code", "link_session", "link_session_token"):
        rows[key] = uuid.uuid4()
    db.sql(
        "UPDATE transfer_recipients SET link_token_hash = sha256(convert_to(:token, 'UTF8')), "
        "link_key_id = 'iso', link_issued_at = now() WHERE id = :id",
        token=str(rows["link_token"]),
        id=rows["recipient"],
    )
    db.sql(
        "INSERT INTO verification_codes (id, tenant_id, recipient_id, code_hmac, hmac_key_id, "
        "expires_at) VALUES (:id, :tenant, :recipient, "
        "sha256(convert_to(CAST(:id AS text), 'UTF8')), 'iso', now() + interval '5 minutes')",
        id=rows["code"],
        tenant=tenant_id,
        recipient=rows["recipient"],
    )
    db.sql(
        "INSERT INTO link_sessions (id, tenant_id, recipient_id, session_hash, expires_at) "
        "VALUES (:id, :tenant, :recipient, sha256(convert_to(:token, 'UTF8')), "
        "now() + interval '1 day')",
        id=rows["link_session"],
        tenant=tenant_id,
        recipient=rows["recipient"],
        token=str(rows["link_session_token"]),
    )
    # Downloads (#180): a grant of the link session for the scanned file, its version the marker
    # the file holds, and an expired one, for the daily cleanup.
    rows["download_grant"], rows["expired_grant"] = uuid.uuid4(), uuid.uuid4()
    for key, age in (("download_grant", "0 seconds"), ("expired_grant", "2 days")):
        db.sql(
            "INSERT INTO download_grants (id, tenant_id, file_id, s3_version_id, recipient_id, "
            "link_session_id, byte_budget, created_at, expires_at) SELECT :id, :tenant, :file, "
            "s3_version_id, :recipient, :session, 30, now() - CAST(:age AS interval), "
            "now() - CAST(:age AS interval) + interval '1 hour' FROM files WHERE id = :file",
            id=rows[key],
            tenant=tenant_id,
            file=rows["scanning_file"],
            recipient=rows["recipient"],
            session=rows["link_session"],
            age=age,
        )
    seed_upload_requests(db, tenant_id, rows)


def seed_upload_requests(db: Sql, tenant_id: uuid.UUID, rows: dict[str, uuid.UUID]) -> None:
    """Upload requests (#212): an open request of the seeded user, its uploader's link, whose
    token is the text of `upload_link_token`, a live code, and a live link session, whose token is
    the text of `upload_session_token`. The marker is in the address and the sealed message."""
    for key in (
        "upload_request",
        "upload_link_token",
        "upload_code",
        "upload_session",
        "upload_session_token",
    ):
        rows[key] = uuid.uuid4()
    db.sql(
        "INSERT INTO upload_requests (id, tenant_id, created_by, state, uploader_email, "
        "email_normalized, locale, message_ct, expires_at, link_token_hash, link_key_id, "
        "link_issued_at, delivery_state) SELECT :id, :tenant, :user, 'open', "
        "split_part(email, '@', 1) || '@uploader.test', split_part(email, '@', 1) || "
        "'@uploader.test', 'en', convert_to(split_part(email, '@', 1), 'UTF8'), "
        "now() - interval '1 minute', sha256(convert_to(:token, 'UTF8')), 'iso', now(), 'sent' "
        "FROM users WHERE id = :user",
        id=rows["upload_request"],
        tenant=tenant_id,
        user=rows["user"],
        token=str(rows["upload_link_token"]),
    )
    db.sql(
        "INSERT INTO verification_codes (id, tenant_id, upload_request_id, code_hmac, "
        "hmac_key_id, expires_at) VALUES (:id, :tenant, :request, "
        "sha256(convert_to(CAST(:id AS text), 'UTF8')), 'iso', now() + interval '5 minutes')",
        id=rows["upload_code"],
        tenant=tenant_id,
        request=rows["upload_request"],
    )
    db.sql(
        "INSERT INTO link_sessions (id, tenant_id, upload_request_id, session_hash, expires_at) "
        "VALUES (:id, :tenant, :request, sha256(convert_to(:token, 'UTF8')), "
        "now() + interval '1 day')",
        id=rows["upload_session"],
        tenant=tenant_id,
        request=rows["upload_request"],
        token=str(rows["upload_session_token"]),
    )
    seed_received_files(db, tenant_id, rows)


def seed_received_files(db: Sql, tenant_id: uuid.UUID, rows: dict[str, uuid.UUID]) -> None:
    """Received files (#213): a clean file of the upload request with its retention, an upload
    still open, the member's grant of the clean file in the seeded member session, and a notice
    due. The marker is in the names and the upload IDs."""
    for key in ("received_file", "received_upload", "member_grant"):
        rows[key] = uuid.uuid4()
    for key, state in (("received_file", "clean"), ("received_upload", "uploading")):
        db.sql(
            "INSERT INTO files (id, tenant_id, upload_request_id, display_name_ct, content_type, "
            "declared_size, actual_size, storage_class, storage_key, s3_upload_id, s3_version_id, "
            "part_size, part_count, state, scan_deadline, inspection_state, retention_until, "
            "delete_after) SELECT :id, :tenant, :request, display_name_ct, 'text/plain', 10, "
            "CASE WHEN :state = 'clean' THEN 10 END, 'standard', "
            "'tenants/' || :tenant || '/files/' || :id, s3_upload_id, "
            "CASE WHEN :state = 'clean' THEN s3_upload_id END, 5242880, 1, :state, "
            "CASE WHEN :state = 'clean' THEN now() + interval '1 hour' END, "
            "CASE WHEN :state = 'clean' THEN 'inspected' ELSE 'pending' END, "
            "CASE WHEN :state = 'clean' THEN now() + interval '30 days' END, "
            "CASE WHEN :state = 'clean' THEN now() + interval '30 days' END "
            "FROM files WHERE id = :template",
            id=rows[key],
            tenant=tenant_id,
            request=rows["upload_request"],
            state=state,
            template=rows["file"],
        )
    db.sql(
        "INSERT INTO download_grants (id, tenant_id, file_id, s3_version_id, user_id, "
        "member_session_id, byte_budget, expires_at) SELECT :id, :tenant, :file, s3_version_id, "
        ":user, :session, 30, now() + interval '1 hour' FROM files WHERE id = :file",
        id=rows["member_grant"],
        tenant=tenant_id,
        file=rows["received_file"],
        user=rows["user"],
        session=rows["session"],
    )
    db.sql(
        "UPDATE upload_requests SET notice_due_at = now() + interval '5 minutes', "
        "arrived_since_notice = 1 WHERE id = :id",
        id=rows["upload_request"],
    )


def seed_dlp(db: Sql, tenant_id: uuid.UUID, marker: str, rows: dict[str, uuid.UUID]) -> None:
    """The DLP policy (#218, revision 0024): the default policy, a keyword list at its second
    revision (the first retired) whose name and terms hold the marker, a rule using it at its
    second revision, and a deleted keyword list that nothing names, for the cleanup."""
    db.sql("SELECT dlp_default_policy(:tenant, :user, 'en')", tenant=tenant_id, user=rows["user"])
    for key in ("dlp_detector", "dlp_rule", "dlp_deleted_detector"):
        rows[key] = uuid.uuid4()
    definition = "\\x00" + ('{"kind":"keywords","terms":["' + marker + '"]}').encode().hex()
    for detector, revision, retired in (
        (rows["dlp_detector"], 1, True),
        (rows["dlp_detector"], 2, False),
        (rows["dlp_deleted_detector"], 1, True),
    ):
        db.sql(
            "INSERT INTO dlp_detectors (id, revision, tenant_id, name, kind, definition_ct, "
            "created_by, retired_at) VALUES (:id, :revision, :tenant, :marker, 'keywords', "
            "CAST(:definition AS bytea), :user, CASE WHEN :retired THEN now() - interval '1 day' "
            "END)",
            id=detector,
            revision=revision,
            tenant=tenant_id,
            marker=marker,
            definition=definition,
            user=rows["user"],
            retired=retired,
        )
    for revision, retired in ((1, True), (2, False)):
        db.sql(
            "INSERT INTO dlp_rules (id, revision, tenant_id, name, direction, condition, "
            "detectors, action, created_by, retired_at) VALUES (:id, :revision, :tenant, :marker, "
            "'sent', 'content', ARRAY['custom:' || CAST(:detector AS text)], 'warn', :user, "
            "CASE WHEN :retired THEN now() - interval '1 day' END)",
            id=rows["dlp_rule"],
            revision=revision,
            tenant=tenant_id,
            marker=marker,
            detector=rows["dlp_detector"],
            user=rows["user"],
            retired=retired,
        )


def seed_dlp_decisions(
    db: Sql, tenant_id: uuid.UUID, marker: str, rows: dict[str, uuid.UUID]
) -> None:
    """The DLP decision (#219, revision 0025): a decision of the draft transfer that matched the
    rule's first, retired revision, the transfer pointing at it, a confirmation whose
    justification holds the marker, a known domain named with the marker, and one 400 days old,
    for the cleanup."""
    for key in ("dlp_decision", "dlp_confirmation"):
        rows[key] = uuid.uuid4()
    db.sql(
        "INSERT INTO dlp_decisions (id, tenant_id, transfer_id, policy_version, mode, outcome, "
        "enforced, untrusted_recipients, new_domains) VALUES (:id, :tenant, :transfer, 1, "
        "'enforce', 'warn', true, 1, 1)",
        id=rows["dlp_decision"],
        tenant=tenant_id,
        transfer=rows["transfer"],
    )
    db.sql(
        "INSERT INTO dlp_decision_rules (decision_id, tenant_id, rule_id, rule_revision, action, "
        "matched_count) VALUES (:decision, :tenant, :rule, 1, 'warn', 3)",
        decision=rows["dlp_decision"],
        tenant=tenant_id,
        rule=rows["dlp_rule"],
    )
    db.sql(
        "UPDATE transfers SET dlp_decision_id = :decision WHERE id = :transfer",
        decision=rows["dlp_decision"],
        transfer=rows["transfer"],
    )
    db.sql(
        "INSERT INTO dlp_confirmations (id, tenant_id, transfer_id, decision_id, confirmed_by, "
        "justification_ct) VALUES (:id, :tenant, :transfer, :decision, :user, "
        "convert_to(:marker, 'UTF8'))",
        id=rows["dlp_confirmation"],
        tenant=tenant_id,
        transfer=rows["transfer"],
        decision=rows["dlp_decision"],
        user=rows["user"],
        marker=marker,
    )
    for domain, age in ((f"{marker}.example", "1 day"), (f"old-{marker}.example", "400 days")):
        db.sql(
            "INSERT INTO dlp_known_domains (tenant_id, domain, first_sent_at, last_sent_at) "
            "VALUES (:tenant, :domain, now() - CAST(:age AS interval), "
            "now() - CAST(:age AS interval))",
            tenant=tenant_id,
            domain=domain,
            age=age,
        )


def seed_dlp_approvals(
    db: Sql, tenant_id: uuid.UUID, marker: str, rows: dict[str, uuid.UUID]
) -> None:
    """DLP approvals (#220, revision 0026): a pending request of the draft transfer for its
    decision and confirmation, past its expiry, for the expiry job's find, and an approval whose
    comment holds the marker."""
    for key in ("dlp_approval_request", "dlp_approval_decision"):
        rows[key] = uuid.uuid4()
    db.sql(
        "INSERT INTO dlp_approval_requests (id, tenant_id, transfer_id, decision_id, "
        "confirmation_id, requested_by, approvals_required, expires_at) VALUES (:id, :tenant, "
        ":transfer, :decision, :confirmation, :user, 1, now() - interval '1 hour')",
        id=rows["dlp_approval_request"],
        tenant=tenant_id,
        transfer=rows["transfer"],
        decision=rows["dlp_decision"],
        confirmation=rows["dlp_confirmation"],
        user=rows["user"],
    )
    db.sql(
        "INSERT INTO dlp_approval_decisions (id, tenant_id, approval_request_id, approver_id, "
        "decision, comment_ct) VALUES (:id, :tenant, :request, :user, 'approve', "
        "convert_to(:marker, 'UTF8'))",
        id=rows["dlp_approval_decision"],
        tenant=tenant_id,
        request=rows["dlp_approval_request"],
        user=rows["user"],
        marker=marker,
    )


def seed_notice_windows(db: Sql, tenant_id: uuid.UUID, rows: dict[str, uuid.UUID]) -> None:
    """Notice windows (#230, revision 0028): the tenant's policy notice with a change waiting and
    due, its capped "no eligible approver" window, and the seeded member's digest window, full and
    due. Each row holds only IDs, kinds and times: the change is a kind, the marker isn't needed."""
    for key, notice, user in (
        ("notice_policy", "dlp_policy_changed", None),
        ("notice_no_approver", "dlp_no_eligible_approver", None),
        ("notice_digest", "dlp_approval_digest", rows["user"]),
    ):
        rows[key] = uuid.uuid4()
        db.sql(
            "INSERT INTO notice_windows (id, tenant_id, notice, user_id, sent, changes, "
            "changed_at, due_at) VALUES (:id, :tenant, :notice, :user, 20, "
            "CASE WHEN :notice = 'dlp_policy_changed' THEN ARRAY['rule_added'] "
            "ELSE '{}'::text[] END, now(), now() + interval '5 minutes')",
            id=rows[key],
            tenant=tenant_id,
            notice=notice,
            user=user,
        )


def seed_dlp_should(db: Sql, tenant_id: uuid.UUID, rows: dict[str, uuid.UUID]) -> None:
    """DLP-6 (#221, revision 0027): a finding of the draft transfer's message, a received file's
    decision that blocked it, and a stop of the tenant's own detector for its budget."""
    for key in ("message_finding", "received_decision"):
        rows[key] = uuid.uuid4()
    db.sql(
        "INSERT INTO dlp_findings (id, tenant_id, transfer_id, detector, count_low, count_medium, "
        "count_high) VALUES (:id, :tenant, :transfer, 'jp_my_number', 0, 0, 2)",
        id=rows["message_finding"],
        tenant=tenant_id,
        transfer=rows["transfer"],
    )
    db.sql(
        "INSERT INTO dlp_decisions (id, tenant_id, file_id, policy_version, mode, outcome, "
        "enforced, untrusted_recipients, new_domains) VALUES (:id, :tenant, :file, 1, "
        "'enforce', 'block', true, 0, 0)",
        id=rows["received_decision"],
        tenant=tenant_id,
        file=rows["received_file"],
    )
    db.sql("UPDATE files SET dlp_blocked = true WHERE id = :file", file=rows["received_file"])
    db.sql(
        "INSERT INTO dlp_pattern_stops (tenant_id, detector_id, files_stopped, last_stopped_at) "
        "VALUES (:tenant, :detector, 2, now())",
        tenant=tenant_id,
        detector=rows["dlp_detector"],
    )


def seed_data_keys(db: Sql, tenant_id: uuid.UUID, marker: str) -> None:
    """Field and DLP data keys (#236, #233; revisions 0031, 0032): a retired version 1 and a live
    version 2 of each, their wrapped keys holding the marker, so a read of theirs shows."""
    for table in ("tenant_data_keys", "tenant_dlp_keys"):
        for version, retired in ((1, True), (2, False)):
            db.sql(
                f"INSERT INTO {table} (tenant_id, key_version, wrapped_key, created_at, "  # noqa: S608
                "retired_at) VALUES (:tenant, :version, convert_to(:marker, 'UTF8') || "
                "decode(repeat('00', 16), 'hex'), now() - interval '2 days', "
                "CASE WHEN :retired THEN now() - interval '1 day' END)",
                tenant=tenant_id,
                version=version,
                marker=marker,
                retired=retired,
            )


def snapshot(admin: Admin, tenants: Sequence[Seeded]) -> list[tuple[object, ...]]:
    """Every row of `tenants`, as the superuser sees it, in one query."""
    parts = [
        # Names from the catalog, not input.
        f"SELECT '{table}' AS t, to_jsonb(x)::text AS r FROM \"{table}\" x "  # noqa: S608
        f"WHERE {'id' if table == 'tenants' else 'tenant_id'} = ANY(:tenants)"
        for table in admin.tenant_tables()
    ]
    return admin.sql(
        " UNION ALL ".join(parts) + " ORDER BY 1, 2", tenants=[t.tenant_id for t in tenants]
    )


def references_to(admin: Admin, tenant: Seeded) -> list[str]:
    """Rows of other tenants that hold one of `tenant`'s IDs in a uuid column, in one query."""
    parts = [
        f"(SELECT '{table}.{column}' FROM \"{table}\" "  # noqa: S608 - names from the catalog
        f'WHERE tenant_id <> :tenant AND "{column}" = ANY(:ids) LIMIT 1)'
        for table, column in admin.uuid_columns()
    ]
    if not parts:
        return []
    rows = admin.sql(" UNION ALL ".join(parts), tenant=tenant.tenant_id, ids=list(tenant.ids()))
    return sorted(str(name) for (name,) in rows)


# ---- running a case ----


def render(value: object) -> str:
    """Everything a result holds, ORM objects' columns included, as text to search."""
    if isinstance(value, DeclarativeBase):
        state = inspect(value)
        return render({a.key: getattr(value, a.key) for a in state.mapper.column_attrs})
    if isinstance(value, Mapping):
        return "{" + ", ".join(f"{render(k)}: {render(v)}" for k, v in value.items()) + "}"
    if isinstance(value, (list, tuple, set, frozenset)) or hasattr(value, "_mapping"):
        return "[" + ", ".join(render(v) for v in value) + "]"  # type: ignore[attr-defined]
    return str(value)


def leaks(result: object, tenant: Seeded) -> list[str]:
    text = render(result)
    return [str(i) for i in tenant.ids() if str(i) in text] + (
        [tenant.marker] if tenant.marker in text else []
    )


def scope_for(kind: ScopeKind, case: Case, mine: Seeded) -> Scope:
    if kind is ScopeKind.TENANT:
        return Scope.tenant(mine.tenant_id)
    if kind is ScopeKind.RESOURCE:
        subject = case.subject(mine) if case.subject else Subject.recipient(uuid.uuid4())
        return Scope.resource(mine.tenant_id, subject)
    return Scope(kind)


@asynccontextmanager
async def pool(db: ScratchDatabase, role: str) -> AsyncIterator[Database]:
    database = Database.connect(db.url(role), pool_size=1)
    try:
        yield database
    finally:
        await database.dispose()


@contextmanager
def _without_the_data_layer() -> Iterator[None]:
    """The test hook of ADR-0020: `in_scope` adds no tenant condition at all, and system scope
    may write tenant rows, so the policies alone must hold."""
    with (
        mock.patch.object(access, "_tenant_condition", return_value=true()),
        mock.patch.object(access, "_writes_tenant_rows_in_system_scope", return_value=True),
    ):
        yield


async def _attempt(database: Database, scope: Scope, case: Case, tenants: Tenants) -> object:
    try:
        async with database.transaction(scope) as session:
            return await case.call(session, tenants)
    except DBAPIError as exc:
        state = getattr(exc.orig, "sqlstate", None)
        if state not in REFUSED:
            raise
        return f"refused ({state})"
    except (NotFoundError, ScopeNotAllowedError) as exc:
        # Only the data layer's own refusals: a KeyError or IndexError is a bug, and fails.
        return f"refused ({type(exc).__name__})"


@dataclass
class World:
    """The isolation suite's databases, by mode. `RLS_ALONE` uses the `AS_BUILT` one."""

    databases: Mapping[Mode, ScratchDatabase]
    _admins: dict[str, Admin] = field(default_factory=dict)

    def database(self, mode: Mode) -> ScratchDatabase:
        return self.databases[Mode.AS_BUILT if mode is Mode.RLS_ALONE else mode]

    def admin(self, mode: Mode) -> Admin:
        db = self.database(mode)
        if db.name not in self._admins:
            self._admins[db.name] = Admin(db)
        return self._admins[db.name]

    def close(self) -> None:
        for admin in self._admins.values():
            admin.dispose()

    async def check(self, case: Case, mode: Mode) -> None:
        db, admin = self.database(mode), self.admin(mode)
        tenants = Tenants(seed_tenant(admin, "mine"), seed_tenant(admin, "theirs"))
        async with AsyncExitStack() as stack:
            pools: dict[str, Database] = {}
            for role, kind, named in case.attempts():
                if role not in pools:  # one pool per role for the whole check
                    pools[role] = await stack.enter_async_context(pool(db, role))
                await self._try(case, mode, admin, pools[role], role, kind, named, tenants)

    async def _try(
        self,
        case: Case,
        mode: Mode,
        admin: Admin,
        database: Database,
        role: str,
        kind: ScopeKind,
        named: bool,
        tenants: Tenants,
    ) -> None:
        where = f"{case.name} as {role} in {kind} scope, {mode}"
        across = named and (kind in _ACROSS or kind in case.across)
        # A scope that reads across tenants must change neither.
        watched = [tenants.theirs, tenants.mine] if across else [tenants.theirs]
        before = snapshot(admin, watched)
        scope = scope_for(kind, case, tenants.mine)
        with _without_the_data_layer() if mode is Mode.RLS_ALONE else nullcontext():
            result = await _attempt(database, scope, case, tenants)
        if not across:
            exposed = [tenants.theirs] + ([tenants.mine] if kind in _TENANTLESS else [])
            for tenant in exposed:
                assert not leaks(result, tenant), f"{where}: read {leaks(result, tenant)}"
        assert snapshot(admin, watched) == before, f"{where}: changed rows"
        referring = references_to(admin, tenants.theirs)
        assert not referring, f"{where}: refers to theirs from {referring}"
