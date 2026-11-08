"""The field key job: backfill, rotation, re-wrap and purge of the tenants' data keys (#236, #233;
encryption and keys 3.2, 3.3, 7.1, 7.2; data model 6).

It runs as the API's workload (`sft.workers.field_keys`), the only one whose role may unwrap field
data keys. It finds the tenants through the `field_key_tenants` lookup function, IDs only, and acts
in each tenant's own scope, one short transaction per batch (data model 2.5), each with its audit
event. Every step is safe to run again: it reads the stored state first.

- **`backfill`** reseals every value of the sealed columns (`sft.data.data_keys.SEALED_COLUMNS`)
  that isn't under the tenant's live key version: format 0 rows of M2's stand-in, which are
  plain text, and rows under a retired version (the re-encryption after a rotation, or after a
  suspected exposure). It makes the tenant's first key version if it has none. Once it has run
  in an environment, a database dump holds no file name or message in plain text; the
  `field_plaintext_reads_total` metric then stays at zero.
- **`rotate`** gives each tenant a new live version once the live one is older than
  `FIELD_KEY_MAX_AGE_DAYS` (yearly, 7.2), and retires the old one, which from then on only
  decrypts. `backfill` afterwards moves the rows over.
- **`rewrap`** wraps every stored data key again with KMS `ReEncrypt`, so the wrapped keys use
  the fields key's newest material (7.1): the key itself doesn't change, so no value is touched.
- **`purge`** deletes retired versions no row uses any more; the foreign keys refuse one that a
  row still names (data model 6).

Its audit events name the tenant, the purpose, versions and counts, never a value:
`fields.resealed`, `data_key.rotated`, `data_key.rewrapped` and `data_key.deleted`, with
`system_actor: field_key_job`. Nothing here logs a value or a key.
"""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator, Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import StrEnum
from typing import Final
from uuid import UUID

from sft.core import sealed
from sft.data import audit, data_keys
from sft.data.audit import Actor, Target
from sft.data.data_keys import SEALED_COLUMNS, KeyPurpose, Sealed
from sft.data.database import Database
from sft.data.models import ActorType
from sft.data.scope import Scope
from sft.service.fields import FieldKeys, TenantKeys

log = logging.getLogger(__name__)

SYSTEM: Final = Actor(ActorType.SYSTEM)
TENANT: Final = "tenant"


class Step(StrEnum):
    BACKFILL = "backfill"
    ROTATE = "rotate"
    REWRAP = "rewrap"
    PURGE = "purge"


class SystemActor(StrEnum):
    FIELD_KEY_JOB = "field_key_job"


@dataclass
class Report:
    tenants: int = 0
    resealed: int = 0
    rotated: int = 0
    rewrapped: int = 0
    deleted: int = 0
    by_column: dict[str, int] = field(default_factory=dict)

    def as_dict(self) -> dict[str, int]:
        return {
            "tenants": self.tenants,
            "resealed": self.resealed,
            "rotated": self.rotated,
            "rewrapped": self.rewrapped,
            "deleted": self.deleted,
            **{f"resealed_{name}": n for name, n in sorted(self.by_column.items())},
        }


class FieldKeyJob:
    """One run of one step over every tenant."""

    def __init__(
        self,
        database: Database,
        keys: FieldKeys,
        *,
        now: Callable[[], datetime],
        batch_size: int = 200,
        max_age: timedelta = timedelta(days=365),
    ) -> None:
        self.database = database
        self.keys = keys
        self.now = now
        self.batch_size = batch_size
        self.max_age = max_age
        self.report = Report()

    async def tenants(self) -> AsyncIterator[UUID]:
        """Every tenant, 500 at a time, through the lookup function."""
        after: UUID | None = None
        while True:
            async with self.database.transaction(Scope.lookup()) as session:
                found = await data_keys.tenants_after(session, after)
            for tenant_id in found:
                yield tenant_id
            if len(found) < 500:
                return
            after = found[-1]

    async def run(self, step: Step) -> Report:
        actions = {
            Step.BACKFILL: self.backfill,
            Step.ROTATE: self.rotate,
            Step.REWRAP: self.rewrap,
            Step.PURGE: self.purge,
        }
        async for tenant_id in self.tenants():
            self.report.tenants += 1
            await actions[step](tenant_id)
        return self.report

    # ---- backfill and re-encryption ----

    async def backfill(self, tenant_id: UUID) -> None:
        for column in SEALED_COLUMNS:
            while await self._reseal_batch(tenant_id, column):
                pass

    async def _reseal_batch(self, tenant_id: UUID, column: Sealed) -> bool:
        """Reseal one batch of the column; whether a full batch was done (so there may be more)."""
        async with self.database.transaction(Scope.tenant(tenant_id)) as session:
            listed = await data_keys.list_keys(session, column.purpose)
            live = next((k.version for k in listed if k.live), None)
            found = await data_keys.stale_values(
                session, column, current=live or 0, limit=self.batch_size
            )
            if not found:
                return False
            keys = await self.keys.tenant(session, tenant_id, column.purpose, write=True)
            done = 0
            for row in found:
                text = _open(keys, column, row.row_id, row.value)
                if await data_keys.reseal(
                    session, column, row, keys.seal(column.column, row.row_id, text)
                ):
                    done += 1
            await audit.record(
                session,
                action="fields.resealed",
                actor=SYSTEM,
                target=Target(TENANT, tenant_id),
                details={
                    "system_actor": SystemActor.FIELD_KEY_JOB,
                    "purpose": column.purpose,
                    "key_version": keys.live,
                    "rows": done,
                },
            )
        self.report.resealed += done
        name = str(column.column)
        self.report.by_column[name] = self.report.by_column.get(name, 0) + done
        return len(found) == self.batch_size

    # ---- rotation ----

    async def rotate(self, tenant_id: UUID) -> None:
        for purpose in sorted(self.keys.purposes):
            async with self.database.transaction(Scope.tenant(tenant_id)) as session:
                listed = await data_keys.list_keys(session, purpose)
                live = next((k for k in listed if k.live), None)
                now = self.now()
                if live is None or now - live.created_at < self.max_age:
                    continue  # nothing sealed yet, or not due: the first write makes version 1
                retired = await data_keys.retire_live(session, purpose, now=now)
                await self.keys.add_version(session, tenant_id, purpose, after=listed)
                await audit.record(
                    session,
                    action="data_key.rotated",
                    actor=SYSTEM,
                    target=Target(TENANT, tenant_id),
                    details={
                        "system_actor": SystemActor.FIELD_KEY_JOB,
                        "purpose": purpose,
                        "retired_version": retired,
                        "key_version": max(k.version for k in listed) + 1,
                    },
                )
            self.report.rotated += 1

    # ---- re-wrap ----

    async def rewrap(self, tenant_id: UUID) -> None:
        for purpose in sorted(self.keys.purposes):
            async with self.database.transaction(Scope.tenant(tenant_id)) as session:
                listed = await data_keys.list_keys(session, purpose)
                done = 0
                for row in listed:
                    wrapped = await self.keys.rewrap(tenant_id, purpose, row)
                    if await data_keys.rewrap(
                        session, purpose, version=row.version, before=row.wrapped, wrapped=wrapped
                    ):
                        done += 1
                if done:
                    await audit.record(
                        session,
                        action="data_key.rewrapped",
                        actor=SYSTEM,
                        target=Target(TENANT, tenant_id),
                        details={
                            "system_actor": SystemActor.FIELD_KEY_JOB,
                            "purpose": purpose,
                            "versions": done,
                        },
                    )
            self.report.rewrapped += done

    # ---- purge ----

    async def purge(self, tenant_id: UUID) -> None:
        for purpose in sorted(self.keys.purposes):
            async with self.database.transaction(Scope.tenant(tenant_id)) as session:
                listed = await data_keys.list_keys(session, purpose)
                used = await data_keys.versions_in_use(session, purpose)
                unused = [k.version for k in listed if not k.live and k.version not in used]
                gone = await data_keys.delete_retired(session, purpose, unused)
                if gone:
                    await audit.record(
                        session,
                        action="data_key.deleted",
                        actor=SYSTEM,
                        target=Target(TENANT, tenant_id),
                        details={
                            "system_actor": SystemActor.FIELD_KEY_JOB,
                            "purpose": purpose,
                            "versions": len(gone),
                        },
                    )
            self.report.deleted += len(gone)


def _open(keys: TenantKeys, column: Sealed, row_id: UUID, value: bytes) -> str:
    """A stored value's text: format 0 as it is, format 1 with the tenant's keys."""
    if sealed.value_format(value) == sealed.PLAINTEXT_FORMAT:
        return sealed.plaintext_of(value).decode("utf-8")
    return keys.open(column.column, row_id, value)


__all__ = ["FieldKeyJob", "KeyPurpose", "Report", "Step", "SystemActor"]
