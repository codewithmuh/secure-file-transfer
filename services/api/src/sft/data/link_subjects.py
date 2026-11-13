"""The subject a link token names: a recipient or an upload request (data model 2.2, 4.2; #212).

`find_by_token` is the credential lookup the link steps run first (`resolveLink`,
`requestVerificationCode`, `createLinkSession`): in lookup scope, by the SHA-256 of the token,
through `lookup_link_subject` (revision 0019), which finds either kind and returns IDs only. The
request then continues in the found tenant's scope, naming the subject in every query.

`sft.data.recipients.find_by_token` is the recipients-only lookup of revision 0013, kept for the
code that revision's schema still serves.
"""

from __future__ import annotations

from dataclasses import dataclass
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from sft.core.tokens import token_hash
from sft.data.access import require_scope
from sft.data.scope import ScopeKind, Subject


@dataclass(frozen=True, slots=True)
class FoundSubject:
    """What the credential lookup returns for a link token: the subject and its tenant."""

    subject: Subject
    tenant_id: UUID


async def find_by_token(session: AsyncSession, token: str) -> FoundSubject | None:
    """The recipient or upload request whose link token this is, and its tenant; None for a
    token no live link has."""
    require_scope(session, ScopeKind.LOOKUP)
    row = (
        await session.execute(
            text(
                "SELECT recipient_id, upload_request_id, owner_tenant_id "
                "FROM lookup_link_subject(:hash)"
            ),
            {"hash": token_hash(token)},
        )
    ).first()
    if row is None:
        return None
    recipient_id, request_id, tenant_id = row[0], row[1], row[2]
    if recipient_id is not None:
        return FoundSubject(Subject.recipient(recipient_id), tenant_id)
    return FoundSubject(Subject.upload_request(request_id), tenant_id)
