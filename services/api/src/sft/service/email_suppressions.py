"""Clearing an address from the tenant's suppression list: `clearEmailSuppression` (#217; FR-7,
FR-27, NFR-14; abuse and rate limits 7.4; data model 2.5).

- **Who** (`email_suppression.clear`, table 6.3): a tenant admin in the web app, acting as one, so
  a local admin needs a passkey sign-in. API keys get `403`: a complaint is the recipient's own
  choice, so a person decides.
- **What it does**: the address, from the request body, is looked up by its pseudonym under every
  key version of the `email-hmac` keyring, and this tenant's live entries for it end now. Nothing
  of another tenant is read or changed (suppressions are per tenant).
- **Always `204`**, whether or not the address was suppressed, so the answer reveals nothing.
- **Audited** (FR-27): `email_suppression.cleared`, with the admin as the actor and never the
  address. `details` takes no text (data model 2.5), so the pseudonym is reached through the
  target: the suppression entry that ended, which holds it. `cleared` says whether one ended. The
  event is written either way, so every clear is on record.
- **At SES**: the notification worker removes the address from the tenant's SES list the first
  time it next sends there, and records `ses_released_at` (`sft.data.suppressions.release_due`).
"""

from __future__ import annotations

from datetime import datetime
from typing import Final

from sft.core.pseudonyms import EmailKeyring
from sft.data import audit, suppressions, users
from sft.data.audit import Origin, Target
from sft.data.database import Database
from sft.data.scope import Scope
from sft.service.caller import Caller
from sft.service.permissions import authorize

ACTION: Final = "email_suppression.cleared"


async def clear_email_suppression(
    database: Database,
    caller: Caller,
    email: str,
    *,
    emails: EmailKeyring,
    origin: Origin,
    now: datetime,
) -> None:
    """`clearEmailSuppression` (module docstring)."""
    authorize(caller, "clearEmailSuppression", now=now)
    if caller.tenant_id is None:  # pragma: no cover - authorize admits tenant callers only
        raise ValueError("a tenant caller has a tenant")
    normalized = users.normalize_email(email)
    async with database.transaction(Scope.tenant(caller.tenant_id)) as session:
        ended = await suppressions.end_entries(session, emails.every_version(normalized))
        await audit.record(
            session,
            action=ACTION,
            actor=caller.actor(),
            # The entry, when one ended: it holds the pseudonym, the record never the address.
            target=Target(suppressions.TARGET, ended[0]) if ended else None,
            origin=origin,
            details={"cleared": bool(ended), "entries": len(ended)},
        )
