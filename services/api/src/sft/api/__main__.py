"""Start the API service: `python -m sft.api`, with settings from the environment."""

from __future__ import annotations

import asyncio
import logging
import sys

from pydantic import ValidationError

from sft.api.server import ApiServer
from sft.core.logs import configure_logging
from sft.core.settings import Settings

log = logging.getLogger("sft.api")

EXIT_BAD_SETTINGS = 2


def main() -> int:
    try:
        settings = Settings()
    except ValidationError as exc:
        configure_logging("info")
        # Which settings are wrong, never their values: one of them may be a secret.
        errors = [
            {"setting": ".".join(map(str, e["loc"])).upper(), "error": e["msg"]}
            for e in exc.errors(include_url=False, include_input=False)
        ]
        log.critical("invalid settings", extra={"errors": errors})
        return EXIT_BAD_SETTINGS
    configure_logging(settings.log_level)
    return asyncio.run(ApiServer(settings).run())


if __name__ == "__main__":
    sys.exit(main())
