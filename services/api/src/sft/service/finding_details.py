"""DLP finding details: location hints and masked previews, encrypted (#233, DLP-8; FR-53, NFR-26;
encryption and keys 3.3; data model 2.7; detectors 7).

**Writing.** The scan worker gets at most 10 location hints and 3 masked previews per finding from
the inspector (`sft.dlp.protocol`), masked as detectors 7 says, never a value. In the transaction
that records the scan (`sft.service.scans.record`) it seals them, as JSON, with the tenant's DLP
data key (`dlp-dek`), bound to the finding's row, into `dlp_findings.detail_ct`. Its database role
can't select that column, so it writes details it can't read back (revision 0011).

**Reading** (`getFileInspection`, `getTransferDlp`). Details are shown only to the file's owner
(the member who made its transfer or upload request) and, for a file of a transfer with an
approval request, to the tenant's active approvers, in a web session (`may_see`). A tenant admin
acting as another member, and every API key, gets the detectors and counts only, with
`details_visible: false`. Every response that holds details writes `dlp_findings.details_read`,
with the target and how many findings it showed, never a hint or a preview. A file whose contents
were deleted has no details any more (the deletion job clears them, data model 6), so it shows
counts only.

**Location hints** are stored as the inspector wrote them (`page 12`, `sheet "顧客一覧", row 340`,
`contracts/2026/appendix.xlsx, slide 4, notes`), and read into the contract's `DlpLocation`: the
hint at the end, and whatever comes before it, an archive member's path, as `member`. A hint this
code doesn't know becomes `part: body`, so a new extractor can't break a read.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable, Sequence
from dataclasses import dataclass, replace
from typing import Final
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from sft.core.ids import uuid7
from sft.data import audit, dlp_approvals, findings
from sft.data.access import tenant_of
from sft.data.audit import Origin, Target
from sft.data.findings import Counts
from sft.service import fields
from sft.service.approval_requests import active_approver
from sft.service.caller import Caller, CallerKind

MAX_LOCATIONS: Final = 10
MAX_PREVIEWS: Final = 3
MAX_PREVIEW_CHARS: Final = 64
READ_ACTION: Final = "dlp_findings.details_read"


@dataclass(frozen=True, slots=True)
class Location:
    """The contract's `DlpLocation`: only the fields that apply are set."""

    member: str | None = None
    page: int | None = None
    sheet: str | None = None
    row: int | None = None
    slide: int | None = None
    line: int | None = None
    paragraph: int | None = None
    part: str | None = None


@dataclass(frozen=True, slots=True)
class Details:
    locations: tuple[Location, ...] = ()
    previews: tuple[str, ...] = ()


# ---- the stored form ----


def encode(locations: Sequence[str], previews: Sequence[str]) -> str:
    """The JSON that is sealed into `detail_ct`: the hints as the inspector wrote them, and the
    previews, each list cut to its limit (FR-53)."""
    body = {
        "locations": [str(h) for h in locations[:MAX_LOCATIONS]],
        "previews": [str(p)[:MAX_PREVIEW_CHARS] for p in previews[:MAX_PREVIEWS]],
    }
    return json.dumps(body, ensure_ascii=False, separators=(",", ":"))


def decode(text: str) -> Details:
    body = json.loads(text)
    if not isinstance(body, dict):
        raise fields.SealedValueError("unreadable finding details")
    hints = [h for h in body.get("locations", []) if isinstance(h, str)][:MAX_LOCATIONS]
    previews = [p for p in body.get("previews", []) if isinstance(p, str)][:MAX_PREVIEWS]
    return Details(tuple(parse_location(h) for h in hints), tuple(previews))


# ---- location hints (detectors 7; sft.dlp.extract) ----

_PARTS: Final = {
    "header": "header",
    "footer": "footer",
    "footnotes": "footnotes",
    "endnotes": "footnotes",
    "comments": "comments",
    "message": "message",
    "document properties": "properties",
    "sheet names": "properties",
}
_NUMBERED: Final = frozenset({"page", "slide", "line", "paragraph", "row"})

_Parser = Callable[[re.Match[str]], Location]
_HINTS: Final[tuple[tuple[re.Pattern[str], _Parser], ...]] = (
    (
        re.compile(r"(?:^|, )slide (\d+), notes$"),
        lambda m: Location(slide=int(m[1]), part="notes"),
    ),
    (
        re.compile(r'(?:^|, )sheet "(.{0,255})", row (\d+)$'),
        lambda m: Location(sheet=m[1], row=int(m[2])),
    ),
    (
        re.compile(r"(?:^|, )(page|slide|line|paragraph|row) (\d+)$"),
        lambda m: _numbered(m[1], int(m[2])),
    ),
    (
        re.compile(r"(?:^|, )(" + "|".join(re.escape(p) for p in _PARTS) + r")$"),
        lambda m: Location(part=_PARTS[m[1]]),
    ),
)


def _numbered(kind: str, number: int) -> Location:
    numbers: dict[str, int | None] = dict.fromkeys(_NUMBERED)
    numbers[kind] = number
    return Location(
        page=numbers["page"],
        row=numbers["row"],
        slide=numbers["slide"],
        line=numbers["line"],
        paragraph=numbers["paragraph"],
    )


def parse_location(hint: str) -> Location:
    """A stored hint as the contract's `DlpLocation`."""
    for pattern, parse in _HINTS:
        found = pattern.search(hint)
        if found is None:
            continue
        location = parse(found)
        if any(getattr(location, n) is not None and getattr(location, n) < 1 for n in _NUMBERED):
            break
        member = hint[: found.start()] or None
        return replace(location, member=member[:1024] if member else None)
    member = hint if hint not in ("", "file") else None
    return Location(member=None if member is None else member[:1024], part="body")


# ---- writing (the scan worker) ----


async def seal_findings(session: AsyncSession, found: Sequence[Counts]) -> list[Counts]:
    """The findings with their details sealed under the tenant's DLP data key, each with the ID
    of the row it is bound to; findings without details pass as they are."""
    if not any(c.locations or c.previews for c in found):
        return list(found)
    tenant_id = tenant_of(session)
    keys = await fields.tenant_keys(session, tenant_id, fields.KeyPurpose.DLP, write=True)
    sealed = []
    for counts in found:
        if not (counts.locations or counts.previews):
            sealed.append(counts)
            continue
        finding_id = uuid7()
        value = keys.seal(
            fields.FINDING_DETAIL, finding_id, encode(counts.locations, counts.previews)
        )
        sealed.append(counts.with_details(finding_id, value))
    return sealed


# ---- reading (the API) ----


async def may_see(
    session: AsyncSession, caller: Caller, *, owner: UUID, transfer_id: UUID | None
) -> bool:
    """Whether the caller sees location hints and previews (FR-53): the owner, or an active
    approver of the transfer's approval request, in a web session. Never an API key, and never a
    tenant admin as such."""
    if caller.kind is not CallerKind.MEMBER or caller.user_id is None:
        return False
    if caller.user_id == owner:
        return True
    if transfer_id is None:
        return False
    if await dlp_approvals.latest_request(session, transfer_id) is None:
        return False
    return await active_approver(session, caller.user_id)


async def read(session: AsyncSession, file_ids: Sequence[UUID]) -> dict[tuple[UUID, str], Details]:
    """The details of the files' findings, by file and detector, opened with the caller's
    tenant's DLP keys. A finding whose details were cleared has none."""
    stored = await findings.details_by_file(session, file_ids)
    if not stored:
        return {}
    keys = await fields.tenant_keys(session, tenant_of(session), fields.KeyPurpose.DLP)
    return {
        (s.file_id, s.detector): decode(keys.open(fields.FINDING_DETAIL, s.finding_id, s.detail_ct))
        for s in stored
    }


async def record_read(
    session: AsyncSession, caller: Caller, target: Target, shown: int, origin: Origin | None
) -> None:
    """The audit event of a response that holds details: who, what, how many; never a value."""
    if shown == 0:
        return
    await audit.record(
        session,
        action=READ_ACTION,
        actor=caller.actor(),
        target=target,
        origin=origin,
        details={"findings": shown},
    )
