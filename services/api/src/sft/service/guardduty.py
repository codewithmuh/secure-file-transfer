"""GuardDuty Malware Protection results for files over 2 GB (ADR-0019; abuse and rate limits 6.4;
#234).

GuardDuty scans every object put in the large-files bucket and publishes a "GuardDuty Malware
Protection Object Scan Result" event; an EventBridge rule sends it to the `guardduty-results`
queue (infra/modules/files-buckets/malware-protection.tf), which the large pool's scan workers
read (`sft.workers.scan.GuardDutyConsumer`). This module reads one event and maps it.

**The event is only a prompt** (T-50). It names a bucket, a key and a version; the worker acts only
if all three name a file of ours, the file is `scanning`, the version is the one completion
recorded, and the object version carries GuardDuty's own tag (`GuardDutyMalwareScanStatus`) with
the same result. A tag that names another result means the event isn't GuardDuty's word for this
version, and it is ignored; a tag not there yet is a retry (GuardDuty may tag after it publishes).

**Mapping** (abuse 6.4), with the inspection `not_inspected` for `too_large`, because the DLP
inspector never reads a file over 2 GB and the tenant's rules for uninspected files decide (FR-47):

| GuardDuty result | File state | `scan_detail` |
|---|---|---|
| `NO_THREATS_FOUND` | `clean` | |
| `THREATS_FOUND` | `infected` | |
| `UNSUPPORTED` with `PASSWORD_PROTECTED` | `unscannable` | `encrypted` |
| `UNSUPPORTED` for any other reason (size, extraction limits) | `unscannable` | `limit_exceeded` |
| `FAILED`, `ACCESS_DENIED` | `scan_failed` | `engine_error` |

GuardDuty retries its own scan before it reports `FAILED`, and offers no call to scan an object
again, so a failure is final at once rather than after our five attempts. No result by the scan
deadline is the sweep's `scan_failed` (`deadline_passed`), as for ClamAV.
"""

from __future__ import annotations

import json
import re
import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Final
from uuid import UUID

from sft.data.models import FileState, InspectionReason, InspectionState, ScanDetail, ScanEngine
from sft.data.outbox import InvalidMessageError, OutboxMessage
from sft.service.scans import InspectionResult, ScanResult

TAG: Final = "GuardDutyMalwareScanStatus"
"""The tag GuardDuty puts on each object version it scanned, with the result's status."""
DETAIL_TYPE: Final = "GuardDuty Malware Protection Object Scan Result"
SOURCE: Final = "aws.guardduty"
TOPIC: Final = "guardduty.result"
"""The envelope's topic, for `processed_messages` and the logs. Not an outbox topic."""

_NAMESPACE: Final = uuid.UUID("0d6b3b6e-8f8a-4c1e-9a55-6f1d2c3b4a59")
"""Fixed: the namespace of every result's derived ID. Never change it."""
_KEY: Final = re.compile(
    r"tenants/(?P<tenant>[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})"
    r"/files/(?P<file>[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})"
)
"""`sft.data.files.storage_key`: IDs only. Anything else in the bucket (GuardDuty's validation
object) isn't a file of ours."""
_VERSION: Final = re.compile(r"[A-Za-z0-9._-]{1,1024}")


class Status(StrEnum):
    """`scanResultStatus`, and the value of GuardDuty's tag."""

    NO_THREATS_FOUND = "NO_THREATS_FOUND"
    THREATS_FOUND = "THREATS_FOUND"
    UNSUPPORTED = "UNSUPPORTED"
    ACCESS_DENIED = "ACCESS_DENIED"
    FAILED = "FAILED"


PASSWORD_PROTECTED: Final = "PASSWORD_PROTECTED"  # noqa: S105 - GuardDuty's reason, not a password
NOT_INSPECTED: Final = InspectionResult(
    InspectionState.NOT_INSPECTED, reasons=(InspectionReason.TOO_LARGE,)
)
"""The DLP inspection of every file GuardDuty scans: over 2 GB, the inspector never reads it."""


@dataclass(frozen=True, slots=True)
class GuardDutyResult:
    """One scan result for a file of ours: which version, and what GuardDuty found."""

    id: UUID
    tenant_id: UUID
    file_id: UUID
    version_id: str
    status: Status
    reasons: tuple[str, ...] = ()

    def as_message(self) -> OutboxMessage:
        """The envelope the consumer framework records and scopes by (`sft.workers.consumer`)."""
        return OutboxMessage(
            id=self.id, topic=TOPIC, tenant_id=self.tenant_id, payload={"file_id": self.file_id}
        )

    def scan_result(self) -> ScanResult:
        """The file's state and reason (module docstring)."""
        if self.status is Status.NO_THREATS_FOUND:
            return ScanResult(FileState.CLEAN, engine=ScanEngine.GUARDDUTY)
        if self.status is Status.THREATS_FOUND:
            return ScanResult(FileState.INFECTED, engine=ScanEngine.GUARDDUTY)
        if self.status is Status.UNSUPPORTED:
            detail = (
                ScanDetail.ENCRYPTED
                if PASSWORD_PROTECTED in self.reasons
                else ScanDetail.LIMIT_EXCEEDED
            )
            return ScanResult(FileState.UNSCANNABLE, detail, engine=ScanEngine.GUARDDUTY)
        return ScanResult(FileState.SCAN_FAILED, ScanDetail.ENGINE_ERROR, ScanEngine.GUARDDUTY)


def _get(value: Any, *path: str) -> Any:
    for name in path:
        value = value.get(name) if isinstance(value, dict) else None
    return value


def parse_result(body: str, *, bucket: str) -> GuardDutyResult | None:
    """The result in a queue message, or None for one that names no file of ours in `bucket`.

    Raises `InvalidMessageError` for a body that isn't a GuardDuty scan result at all; it then goes
    to the dead-letter queue, which alerts."""
    try:
        raw = json.loads(body)
    except (ValueError, TypeError, RecursionError) as exc:
        raise InvalidMessageError("not a GuardDuty scan result") from exc
    if (
        not isinstance(raw, dict)
        or raw.get("source") != SOURCE
        or raw.get("detail-type") != DETAIL_TYPE
        or not isinstance(raw.get("id"), str)
    ):
        raise InvalidMessageError("not a GuardDuty scan result")
    detail = raw.get("detail")
    status = _get(detail, "scanResultDetails", "scanResultStatus")
    if status not in set(Status):
        raise InvalidMessageError("a GuardDuty scan result without a known status")
    if _get(detail, "s3ObjectDetails", "bucketName") != bucket:
        return None  # another bucket: the rule's pattern names ours, so never ours to act on
    key = _get(detail, "s3ObjectDetails", "objectKey")
    version = _get(detail, "s3ObjectDetails", "versionId")
    found = _KEY.fullmatch(key) if isinstance(key, str) else None
    if found is None or not isinstance(version, str) or not _VERSION.fullmatch(version):
        return None  # GuardDuty's validation object, or an object that isn't a file
    listed = _get(detail, "scanResultDetails", "statusReasons")
    reasons = tuple(r for r in listed if isinstance(r, str)) if isinstance(listed, list) else ()
    return GuardDutyResult(
        # One ID per event: SQS and EventBridge may deliver it twice, and the record makes the
        # second a duplicate. The version keeps a re-uploaded object's result apart.
        id=uuid.uuid5(_NAMESPACE, f"{raw['id']}/{version}"),
        tenant_id=UUID(found["tenant"]),
        file_id=UUID(found["file"]),
        version_id=version,
        status=Status(status),
        reasons=reasons,
    )


class TagCheck(StrEnum):
    """What GuardDuty's tag on the version says about the event."""

    MATCHES = "matches"
    MISSING = "missing"
    """Not tagged yet: GuardDuty may tag after it publishes. Try again later."""
    DIFFERS = "differs"
    """Another result: not GuardDuty's word for this version. Ignored."""


def check_tag(result: GuardDutyResult, tags: Mapping[str, str]) -> TagCheck:
    value = tags.get(TAG)
    if value is None:
        return TagCheck.MISSING
    return TagCheck.MATCHES if value == result.status.value else TagCheck.DIFFERS


def event_body(
    *,
    event_id: str,
    bucket: str,
    key: str,
    version_id: str,
    status: Status,
    reasons: tuple[str, ...] = (),
    time: str,
    region: str = "ap-northeast-1",
) -> str:
    """A scan result event as EventBridge delivers it: the local stand-in's (#234) and the tests'.
    The account is a placeholder; nothing reads it."""
    completed = status in (Status.NO_THREATS_FOUND, Status.THREATS_FOUND)
    skipped = status in (Status.UNSUPPORTED, Status.ACCESS_DENIED)
    return json.dumps(
        {
            "version": "0",
            "id": event_id,
            "detail-type": DETAIL_TYPE,
            "source": SOURCE,
            "account": "000000000000",
            "time": time,
            "region": region,
            "resources": [],
            "detail": {
                "schemaVersion": "1.0",
                "scanStatus": "COMPLETED" if completed else "SKIPPED" if skipped else "FAILED",
                "resourceType": "S3_OBJECT",
                "s3ObjectDetails": {
                    "bucketName": bucket,
                    "objectKey": key,
                    "versionId": version_id,
                    "s3Throttled": False,
                },
                "scanResultDetails": {
                    "scanResultStatus": status.value,
                    "threats": None,
                    "statusReasons": list(reasons) or None,
                },
            },
        }
    )
