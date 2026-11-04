"""Start the API service: `python -m sft.api`, with settings from the environment."""

from __future__ import annotations

import asyncio
import sys

from sft.api.server import ApiServer
from sft.core.logs import configure_logging
from sft.core.settings import EXIT_BAD_SETTINGS, Settings, load_settings
from sft.core.telemetry import configure_tracing

SERVICE_NAME = "sft-api"


def main() -> int:
    # Bad settings: one log line naming them, never their values (sft.core.settings).
    settings = load_settings(Settings)
    if settings is None:
        return EXIT_BAD_SETTINGS
    configure_logging(settings.log_level)
    tracing = configure_tracing(
        SERVICE_NAME, settings.app_version, settings.otel_exporter_otlp_endpoint
    )
    try:
        return asyncio.run(ApiServer(settings).run())
    finally:
        # After the drain: export the spans still buffered, waiting a few seconds at most.
        tracing.shutdown()


if __name__ == "__main__":
    sys.exit(main())
