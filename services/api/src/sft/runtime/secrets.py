"""Keyrings read from Secrets Manager at start and every 5 minutes (encryption and keys 6.4, 6.5).

A keyring setting either holds the keyring (the local stack, the tests) or names its secret,
`secretsmanager:sft/<env>/app/<name>` (`sft.core.keyrings`). `Keyrings.load` returns the keyring
either way. For a named secret it reads the secret once, through the region's VPC endpoint, and the
process doesn't start if it can't read it or the keyring is malformed (6.5).

`Keyrings.run` then reads every named secret every 5 minutes and swaps a new version into its
keyring in place (`reload`), so each step of a rotation (stage, activate, retire) reaches every pod
within one interval, with no restart (#162, #184). A failed read or a malformed version keeps the
keyring that is loaded: a warning names the keyring, never a value, and
`sft_keyring_refresh_failures_total` counts it. The rotation job waits three intervals between
steps (6.5), so one failed refresh delays nothing; `sft_keyring_refreshed_timestamp_seconds` says
when each keyring was last read.

The values stay in this process's memory: never on disk, in the environment or in a log.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any, Final, Protocol, cast

import boto3
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError
from prometheus_client import CollectorRegistry, Counter, Gauge
from pydantic import SecretStr

from sft.core.keyrings import KeyringError, secret_reference

log = logging.getLogger(__name__)

REFRESH_SECONDS: Final = 300.0
"""How often a named secret is read again: encryption and keys 6.4's 5 minutes."""


class Reloadable(Protocol):
    def reload(self, raw: str) -> None: ...


class SecretsClient(Protocol):
    """The one Secrets Manager call the keyrings need."""

    def get_secret_value(self, *, SecretId: str) -> Mapping[str, Any]: ...  # noqa: N803


class KeyringUnavailableError(RuntimeError):
    """A named keyring couldn't be read at startup. The message names it, never a value."""


@dataclass(frozen=True, slots=True)
class KeyringMetrics:
    failures: Counter
    refreshed: Gauge

    @classmethod
    def create(cls, registry: CollectorRegistry) -> KeyringMetrics:
        return cls(
            Counter(
                "sft_keyring_refresh_failures_total",
                "Reads of a keyring's secret that failed or held a malformed keyring; the "
                "loaded version stays.",
                ["keyring"],
                registry=registry,
            ),
            Gauge(
                "sft_keyring_refreshed_timestamp_seconds",
                "When each keyring's secret was last read and loaded.",
                ["keyring"],
                registry=registry,
            ),
        )


@dataclass(slots=True)
class _Named:
    name: str
    secret_id: str
    keyring: Reloadable
    version: str | None


class Keyrings:
    """The process's keyrings that name a secret, and their refresh."""

    def __init__(
        self,
        client: Callable[[], SecretsClient],
        metrics: KeyringMetrics,
        *,
        interval: float = REFRESH_SECONDS,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._client_factory = client
        self._client: SecretsClient | None = None
        self._metrics = metrics
        self._interval = interval
        self._clock = clock
        self._named: list[_Named] = []

    @classmethod
    def create(
        cls, *, region: str, registry: CollectorRegistry, endpoint_url: str | None = None
    ) -> Keyrings:
        """Keyrings whose secrets are read in `region`. The client is made only if one is named."""

        def client() -> SecretsClient:
            made = boto3.client(
                "secretsmanager",
                region_name=region,
                endpoint_url=endpoint_url,
                config=Config(retries={"mode": "standard", "max_attempts": 3}),
            )
            return cast(SecretsClient, made)

        return cls(client, KeyringMetrics.create(registry))

    @property
    def named(self) -> tuple[str, ...]:
        """The keyrings read from Secrets Manager, by name."""
        return tuple(n.name for n in self._named)

    async def load[K: Reloadable](
        self, setting: SecretStr, parse: Callable[[str], K], *, name: str
    ) -> K:
        """The keyring a setting holds or names; `parse` is its class's `from_json`."""
        raw = setting.get_secret_value()
        secret_id = secret_reference(raw, name=name)
        if secret_id is None:
            return parse(raw)
        try:
            value, version = await asyncio.to_thread(self._read, secret_id)
            keyring = parse(value)
        except (BotoCoreError, ClientError, KeyringError, ValueError) as exc:
            # A keyring error names the keyring and a key ID at most; a client error, its code.
            raise KeyringUnavailableError(
                f"the {name} keyring can't be loaded: {_reason(exc)}"
            ) from exc
        self._named.append(_Named(name, secret_id, keyring, version))
        self._metrics.refreshed.labels(name).set(self._clock())
        return keyring

    async def refresh(self) -> None:
        """Read every named secret once; load each version that changed."""
        for named in self._named:
            try:
                value, version = await asyncio.to_thread(self._read, named.secret_id)
                if version is not None and version == named.version:
                    self._metrics.refreshed.labels(named.name).set(self._clock())
                    continue
                named.keyring.reload(value)
            except (BotoCoreError, ClientError, KeyringError, ValueError) as exc:
                self._metrics.failures.labels(named.name).inc()
                log.warning(
                    "keyring refresh failed; the loaded version stays",
                    extra={"keyring": named.name, "reason": _reason(exc)},
                )
                continue
            if named.version is not None:
                log.info("keyring reloaded", extra={"keyring": named.name})
            named.version = version
            self._metrics.refreshed.labels(named.name).set(self._clock())

    async def run(self) -> None:
        """Refresh every `interval` until cancelled. Does nothing if no keyring names a secret."""
        if not self._named:
            return
        while True:
            await asyncio.sleep(self._interval)
            await self.refresh()

    def _read(self, secret_id: str) -> tuple[str, str | None]:
        if self._client is None:
            self._client = self._client_factory()
        answer = self._client.get_secret_value(SecretId=secret_id)
        value = answer.get("SecretString")
        if not isinstance(value, str):
            raise KeyringError("the secret holds no string")
        version = answer.get("VersionId")
        return value, version if isinstance(version, str) else None


def _reason(exc: Exception) -> str:
    """Why a read failed, without a value: a client error's code, or a keyring error's message."""
    if isinstance(exc, ClientError):
        return str(exc.response.get("Error", {}).get("Code", "ClientError"))
    if isinstance(exc, KeyringError):
        return str(exc)
    return type(exc).__name__
