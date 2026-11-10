"""The contract's `Tenant`, the one model both apps answer with (#161): `GET /me` on the public app
and the tenant operations of the operator API."""

from __future__ import annotations

from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel

from sft.data.models import Tenant as TenantRow

TenantStatus = Literal["active", "suspended"]


class Tenant(BaseModel):
    id: UUID
    name: str
    status: TenantStatus
    created_at: datetime

    @classmethod
    def of(cls, row: TenantRow) -> Tenant:
        # The table's CHECK allows only the two statuses.
        return cls(id=row.id, name=row.name, status=row.status, created_at=row.created_at)  # type: ignore[arg-type]
