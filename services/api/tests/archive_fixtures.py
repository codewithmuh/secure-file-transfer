"""An in-memory audit archive for the tests (#177): `FakeArchiveStore` stands in for both regions'
buckets, and `fake_archive` builds the `AuditArchive` the apps and services take.

`fail` makes a region's writes fail, as an outage of that region's archive would; `objects` holds
what each region was given, by key, exactly once, as the conditional write keeps it.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field

from prometheus_client import CollectorRegistry

from sft.service.audit_archive import ArchiveMetrics, ArchiveWriteError, AuditArchive, Region


@dataclass
class FakeArchiveStore:
    regions: tuple[Region, ...] = (Region.TOKYO, Region.OSAKA)
    objects: dict[Region, dict[str, bytes]] = field(default_factory=dict)
    fail: set[Region] = field(default_factory=set)
    writes: int = 0

    async def put_once(
        self, region: Region, key: str, body: bytes, *, content_type: str = "application/json"
    ) -> bool:
        self.writes += 1
        if region in self.fail:
            raise ArchiveWriteError("ServiceUnavailable")
        held = self.objects.setdefault(region, {})
        if key in held:
            return False
        held[key] = body
        return True

    async def close(self) -> None:
        pass

    def records(self, region: Region = Region.TOKYO) -> list[dict[str, object]]:
        return [json.loads(body) for body in self.objects.get(region, {}).values()]

    def actions(self, region: Region = Region.TOKYO) -> list[object]:
        return sorted(str(r["action"]) for r in self.records(region))


def fake_archive(store: FakeArchiveStore | None = None) -> AuditArchive:
    return AuditArchive(store or FakeArchiveStore(), ArchiveMetrics.create(CollectorRegistry()))
