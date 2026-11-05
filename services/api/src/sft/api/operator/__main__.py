"""Start the operator API: `python -m sft.api.operator`, with settings from the environment."""

from __future__ import annotations

import asyncio
import sys

from sft.api.operator.app import create_operator_app
from sft.api.server import ApiServer
from sft.core.logs import configure_logging
from sft.core.settings import EXIT_BAD_SETTINGS, OperatorSettings, load_settings


def main() -> int:
    # Bad settings: one log line naming them, never their values (sft.core.settings).
    settings = load_settings(OperatorSettings)
    if settings is None:
        return EXIT_BAD_SETTINGS
    configure_logging(settings.log_level)
    # The server's registry, so the app's counter metrics are on the /metrics it serves.
    server = ApiServer(
        settings, make_app=lambda registry: create_operator_app(settings, registry=registry)
    )
    return asyncio.run(server.run())


if __name__ == "__main__":
    sys.exit(main())
