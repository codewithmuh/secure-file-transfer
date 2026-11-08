"""The key rotation job's rules (encryption and keys 6.4, 6.5, 7.2; #185): what each run writes.

The job is the only writer of the `sft/<env>/app/*` secrets. Terraform creates them without a
value (infra/modules/app-secrets), so the job's first run writes every first version, and the API
and the notification worker start only after it. Each later run, hourly, takes at most one step
per secret:

- **A keyring** (`csrf-hmac`, `email-hmac`, `code-hmac`, `link-hmac`) goes through 6.5's three
  steps. *Stage* a new key once the active key is older than its period. *Activate* it once it has
  been staged for `STAGE_DELAY`, every pod having loaded it by then: the old key becomes `verify`,
  with `retire_after` its overlap later. *Retire* a `verify` key once `retire_after` has passed.
  An `email-hmac` key is never retired here: it leaves only when no suppression row uses it,
  which the job can't see (it has no database role), so that is an operator's step for now.
- **An app client** (`idp-client/<region>`, one per user pool) gets a second client secret from
  Cognito (`AddUserPoolClientSecret`; Cognito holds two at most), which the job writes, once the
  stored one is older than a year or isn't live; the first run replaces the secret Cognito made
  when Terraform created the client, which is in Terraform's state. An older client secret is
  deleted once the stored one has been in place for `CLIENT_SECRET_OVERLAP` (this region) or
  `REMOTE_CLIENT_SECRET_OVERLAP` (Osaka's, whose pods this job can't restart).

The workloads read the keyrings from Secrets Manager themselves, at start and every 5 minutes
(`sft.runtime.secrets`, #184), so a keyring step needs nothing more. The API reads this region's
app client through External Secrets at start, so after a new client secret here the job has the
API load it (`Reloader`). A value never appears in a log line, a message or a repr; a report
names secrets and key IDs only.
"""

from __future__ import annotations

import base64
import json
import logging
import secrets
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any, Final, Protocol

from sft.core.hmac_keyrings import CODE_KEY_ID, LINK_KEY_ID
from sft.core.keyrings import CSRF_KEY_ID, EMAIL_KEY_ID, KeyringError, parse_keyring
from sft.core.settings import IdpClient

log = logging.getLogger(__name__)

KEY_BYTES: Final = 32
STAGE_DELAY: Final = timedelta(minutes=15)
"""Three of the pods' refresh intervals (6.5); the hourly schedule makes it an hour in practice."""
CLIENT_SECRET_OVERLAP: Final = timedelta(minutes=15)
REMOTE_CLIENT_SECRET_OVERLAP: Final = timedelta(days=1)
CLIENT_SECRET_PERIOD: Final = timedelta(days=365)


@dataclass(frozen=True, slots=True)
class KeyringPolicy:
    """One keyring's period and overlap (6.5's table)."""

    name: str
    period: timedelta
    overlap: timedelta
    key_id: Any
    needs_activation: bool = False
    retires: bool = True


KEYRINGS: Final = (
    KeyringPolicy("csrf-hmac", timedelta(days=90), timedelta(hours=24), CSRF_KEY_ID),
    KeyringPolicy(
        "email-hmac",
        timedelta(days=365),
        timedelta(days=90),
        EMAIL_KEY_ID,
        needs_activation=True,
        retires=False,
    ),
    KeyringPolicy("code-hmac", timedelta(days=90), timedelta(hours=24), CODE_KEY_ID),
    KeyringPolicy("link-hmac", timedelta(days=90), timedelta(days=14), LINK_KEY_ID),
)


class RotationError(Exception):
    """A step failed; the message names the secret and AWS's error code, never a value."""


class SecretStore(Protocol):
    async def read(self, name: str, *, region: str) -> str | None:
        """The current value of `name` in `region`, or None when it has none yet."""

    async def write(self, name: str, value: str, *, region: str) -> None: ...


@dataclass(frozen=True, slots=True)
class ClientSecret:
    id: str
    created_at: datetime


class ClientSecrets(Protocol):
    async def list(self, client: IdpClient) -> Sequence[ClientSecret]: ...

    async def add(self, client: IdpClient) -> tuple[ClientSecret, str]:
        """A new client secret, and its value."""

    async def delete(self, client: IdpClient, secret_id: str) -> None: ...


class Reloader(Protocol):
    async def reload(self) -> None:
        """Have the workloads load the secrets' current versions."""


@dataclass(slots=True)
class Report:
    """What a run did, by secret: `written` (first version), `staged`, `activated`, `retired`,
    `added` (a client secret), `deleted` (an older client secret). Holds no value."""

    steps: list[dict[str, str]] = field(default_factory=list)

    def add(self, secret: str, step: str, **ids: str) -> None:
        self.steps.append({"secret": secret, "step": step, **ids})


def _new_key(now: datetime, *, active: bool, needs_activation: bool) -> dict[str, str]:
    entry = {
        "id": "k" + now.strftime("%Y%m%d%H%M"),
        "state": "active" if active else "staged",
        "key": base64.b64encode(secrets.token_bytes(KEY_BYTES)).decode(),
        "created_at": now.isoformat(),
    }
    if active and needs_activation:
        entry["activated_at"] = now.isoformat()
    return entry


def _time(entry: dict[str, Any], key: str) -> datetime | None:
    value = entry.get(key)
    return datetime.fromisoformat(value) if isinstance(value, str) else None


def next_keyring(
    raw: str | None, policy: KeyringPolicy, now: datetime
) -> tuple[str, str, str] | None:
    """The keyring after this run's one step, with the step and the key ID it concerns; None when
    nothing is due. `KeyringError` for a stored keyring the workloads would refuse too."""
    if raw is None:
        entry = _new_key(now, active=True, needs_activation=policy.needs_activation)
        return json.dumps([entry]), "written", entry["id"]
    parse_keyring(
        raw, name=policy.name, key_id=policy.key_id, needs_activation=policy.needs_activation
    )
    entries: list[dict[str, Any]] = json.loads(raw)
    [active] = [e for e in entries if e["state"] == "active"]
    staged = [e for e in entries if e["state"] == "staged"]
    for entry in staged:
        created = _time(entry, "created_at")
        if created is None or created + STAGE_DELAY > now:
            continue
        active["state"], active["retire_after"] = "verify", (now + policy.overlap).isoformat()
        active.pop("activated_at", None)
        entry["state"] = "active"
        if policy.needs_activation:
            entry["activated_at"] = now.isoformat()
        return json.dumps(entries), "activated", str(entry["id"])
    if policy.retires:
        for entry in entries:
            retire_after = _time(entry, "retire_after")
            if entry["state"] == "verify" and retire_after is not None and retire_after <= now:
                entries.remove(entry)
                return json.dumps(entries), "retired", str(entry["id"])
    since = _time(active, "activated_at") or _time(active, "created_at")
    if not staged and (since is None or since + policy.period <= now):
        entry = _new_key(now, active=False, needs_activation=policy.needs_activation)
        if any(e["id"] == entry["id"] for e in entries):
            return None  # a key made this minute already; the next run stages it
        return json.dumps([*entries, entry]), "staged", entry["id"]
    return None


def _secret_name(environment: str, name: str) -> str:
    return f"sft/{environment}/app/{name}"


class KeyRotation:
    """One run: every keyring, then every app client, then one reload if this region's client
    secret changed."""

    def __init__(
        self,
        *,
        environment: str,
        region: str,
        store: SecretStore,
        client_secrets: ClientSecrets,
        clients: Sequence[IdpClient],
        reloader: Reloader | None,
    ) -> None:
        self.environment = environment
        self.region = region
        self.store = store
        self.client_secrets = client_secrets
        self.clients = clients
        self.reloader = reloader

    async def run(self, now: datetime | None = None) -> Report:
        now = now or datetime.now(UTC)
        report = Report()
        for policy in KEYRINGS:
            await self._keyring(policy, now, report)
        for client in self.clients:
            await self._client(client, now, report)
        local_client = _secret_name(self.environment, f"idp-client/{self.region}")
        if self.reloader is not None and any(
            s["secret"] == local_client and s["step"] == "added" for s in report.steps
        ):
            await self.reloader.reload()
        return report

    async def _keyring(self, policy: KeyringPolicy, now: datetime, report: Report) -> None:
        name = _secret_name(self.environment, policy.name)
        raw = await self.store.read(name, region=self.region)
        try:
            step = next_keyring(raw, policy, now)
        except KeyringError as exc:
            raise RotationError(f"{name} can't be read: {exc}") from None
        if step is None:
            return
        value, kind, key_id = step
        await self.store.write(name, value, region=self.region)
        report.add(name, kind, key_id=key_id)

    async def _client(self, client: IdpClient, now: datetime, report: Report) -> None:
        name = _secret_name(self.environment, f"idp-client/{client.region}")
        stored = await self.store.read(name, region=client.region)
        stored_id, written_at = _stored_client_secret(stored, client)
        live = await self.client_secrets.list(client)
        current = next((s for s in live if s.id == stored_id), None)
        if current is None or current.created_at + CLIENT_SECRET_PERIOD <= now:
            # Room for the new one: Cognito holds two, and the stored one is kept if it is live.
            for old in sorted(live, key=lambda s: s.created_at):
                if len(live) < 2:
                    break
                if old is not current:
                    await self.client_secrets.delete(client, old.id)
                    live = [s for s in live if s is not old]
                    report.add(name, "deleted", client_secret_id=old.id)
            added, value = await self.client_secrets.add(client)
            document = {
                "client_id": client.client_id,
                "client_secret": value,
                "client_secret_id": added.id,
                "written_at": now.isoformat(),
            }
            await self.store.write(name, json.dumps(document), region=client.region)
            report.add(name, "added", client_secret_id=added.id)
            return
        overlap = (
            CLIENT_SECRET_OVERLAP if client.region == self.region else REMOTE_CLIENT_SECRET_OVERLAP
        )
        if written_at is not None and written_at + overlap <= now:
            for old in live:
                if old is not current:
                    await self.client_secrets.delete(client, old.id)
                    report.add(name, "deleted", client_secret_id=old.id)


def _stored_client_secret(raw: str | None, client: IdpClient) -> tuple[str | None, datetime | None]:
    """The stored client secret's ID and when it was written; (None, None) when there is none, or
    it is for another client (the pool or client was made again)."""
    if raw is None:
        return None, None
    try:
        document = json.loads(raw)
    except json.JSONDecodeError:
        return None, None
    if not isinstance(document, dict) or document.get("client_id") != client.client_id:
        return None, None
    secret_id, written = document.get("client_secret_id"), document.get("written_at")
    try:
        written_at = datetime.fromisoformat(written) if isinstance(written, str) else None
    except ValueError:
        written_at = None
    return (secret_id if isinstance(secret_id, str) else None), written_at
