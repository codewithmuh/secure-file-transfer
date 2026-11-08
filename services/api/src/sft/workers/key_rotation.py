"""The key rotation job's entry point (encryption and keys 6.4, 6.5; #185): one run, then exit.

    python -m sft.workers.key_rotation

The chart runs it hourly in Tokyo only, as the `key-rotation` CronJob with its own role. What a run
does is `sft.service.key_rotation`'s. It logs its report as one JSON line, which names secrets,
steps and key IDs, never a value. It exits 0 when the run finished, 1 when a step failed (the next
run is the retry: every step reads the stored state first), and 2 on bad settings.
"""

from __future__ import annotations

import asyncio
import logging
import sys
from typing import Final

from sft.core.logs import configure_logging
from sft.core.settings import EXIT_BAD_SETTINGS, KeyRotationSettings, load_settings
from sft.runtime.key_rotation import CognitoClientSecrets, KubernetesReloader, SecretsManagerStore
from sft.service.key_rotation import KeyRotation, RotationError

log = logging.getLogger(__name__)

EXIT_FAILED: Final = 1


async def run(settings: KeyRotationSettings) -> int:
    regions = sorted({settings.aws_region, *(c.region for c in settings.idp_clients)})
    reloader = None
    if settings.restart_deployments:
        reloader = KubernetesReloader.create(
            url=settings.kubernetes_url,
            token_path=settings.kubernetes_token_path,
            ca_path=settings.kubernetes_ca_path,
            namespace=settings.kubernetes_namespace,
            external_secrets=settings.external_secrets,
            deployments=settings.restart_deployments,
        )
    rotation = KeyRotation(
        environment=settings.environment,
        region=settings.aws_region,
        store=SecretsManagerStore.create(regions),
        client_secrets=CognitoClientSecrets.create(regions),
        clients=settings.idp_clients,
        reloader=reloader,
    )
    try:
        report = await rotation.run()
    except RotationError as exc:
        log.error("key rotation failed; the next run retries", extra={"error": str(exc)})
        return EXIT_FAILED
    finally:
        if reloader is not None:
            await reloader.aclose()
    log.info("key rotation done", extra={"steps": report.steps})
    return 0


def main() -> int:
    settings = load_settings(KeyRotationSettings)
    if settings is None:
        return EXIT_BAD_SETTINGS
    configure_logging(settings.log_level)
    return asyncio.run(run(settings))


if __name__ == "__main__":
    sys.exit(main())
