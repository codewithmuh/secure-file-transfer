"""The upload limits that aren't rates (abuse and rate limits 2.2 F, 6.1; #165).

- **The tenant's daily upload volume:** 200 GB of declared files per UTC day, members', API
  keys' and uploaders' together, since an uploader's files count against the requesting tenant
  (abuse 6.1). A `Budget` in megabytes, as group D's byte caps are: a declaration peeks it before
  it starts the multipart upload, and charges it as the last step of the transaction that
  declares the file, so a refusal there rolls the declaration back and a declaration that fails
  first charges nothing. A rejected or removed file keeps its charge: the cap is on volume
  declared, so rejected uploads can't be replayed for free (AB-5). Over the cap is `429` with
  `Retry-After` until the day ends. A fixed day, not a sliding 24 hours, as for downloads: the
  worst case is twice the cap across midnight. It fails open to the per-pod limiter, at a third.
- **Part URLs per file:** at most 10 times the file's `part_count` over its life, counted in
  PostgreSQL with the file (`files.part_urls_issued`, revision 0033), because a file may keep
  uploading for longer than the counter store's 25-hour keys. Over the cap is `429` with
  `Retry-After: 86400`: no wait frees more URLs for that file, and its unfinished upload is
  rejected a day after its last part; the client declares the file again.
"""

from __future__ import annotations

import logging
from collections.abc import Mapping
from typing import Final

from sft.core.errors import RateLimited
from sft.service.rate_limits.downloads import units
from sft.service.rate_limits.limiter import Charge
from sft.service.rate_limits.limits import DAY, Budget, Group, KeyType, KeyValue, Limit

log = logging.getLogger(__name__)

F_TENANT_UPLOAD_BYTES = Limit(
    Group.UPLOADS, "tenant_upload_bytes", (KeyType.TENANT,), Budget(200_000, DAY)
)
"""200 GB of declared uploads per tenant per UTC day, in megabytes (abuse 2.2 F, 6.1). Not in
`limits.ALL`, whose table-driven tests count requests one at a time."""

PART_URLS_PER_PART: Final = 10
"""A file's part URLs over its life: 10 times its `part_count` (abuse 6.1)."""
PART_URL_CAP_ID: Final = f"{Group.UPLOADS.value}.file_part_urls"
PART_URL_CAP_RETRY_AFTER: Final = DAY


def upload_charges(keys: Mapping[KeyType, KeyValue], size: int) -> list[Charge]:
    """What declaring a file of `size` bytes costs: its megabytes, rounded up, against the
    tenant's day. Peek before the multipart upload starts; charge in the declaring transaction."""
    return [Charge(F_TENANT_UPLOAD_BYTES, keys, units(size))]


def part_url_cap(part_count: int) -> int:
    return PART_URLS_PER_PART * part_count


def part_urls_refused() -> RateLimited:
    """The answer when a file has had all its part URLs (module docstring)."""
    log.info("rate limited", extra={"limits": [PART_URL_CAP_ID]})
    return RateLimited(retry_after=PART_URL_CAP_RETRY_AFTER)
