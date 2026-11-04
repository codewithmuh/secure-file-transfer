"""Start the API service: `python -m sft.api`, with settings from the environment."""

from __future__ import annotations

import asyncio
import logging
import re
import sys

from pydantic import ValidationError

from sft.api.server import ApiServer
from sft.core.logs import configure_logging
from sft.core.settings import Settings

log = logging.getLogger("sft.api")

EXIT_BAD_SETTINGS = 2


def setting_errors(exc: ValidationError) -> list[dict[str, str]]:
    """Which settings are wrong and why, never their values: one of them may be a secret."""
    names = [name.upper() for name in Settings.model_fields]
    errors = []
    for error in exc.errors(include_url=False, include_input=False):
        if error["loc"]:
            setting = ".".join(map(str, error["loc"])).upper()
        else:
            # A check across settings, such as the two ports differing, has no location; its
            # message names the settings it checks.
            named = [name for name in names if re.search(rf"\b{name}\b", error["msg"])]
            setting = ", ".join(named) or "(see error)"
        errors.append({"setting": setting, "error": error["msg"]})
    return errors


def main() -> int:
    try:
        settings = Settings()
    except ValidationError as exc:
        configure_logging("info")
        log.critical("invalid settings", extra={"errors": setting_errors(exc)})
        return EXIT_BAD_SETTINGS
    configure_logging(settings.log_level)
    return asyncio.run(ApiServer(settings).run())


if __name__ == "__main__":
    sys.exit(main())
