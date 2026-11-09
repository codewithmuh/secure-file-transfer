"""The metadata purge (#224), one run (`sft.service.lifecycle`, data model 6): the module the
chart's daily CronJob runs. `python -m sft.workers.jobs purge` is the same run."""

from __future__ import annotations

import sys

from sft.service.lifecycle import Job
from sft.workers.jobs import main as run


def main() -> int:
    return run([], job=Job.PURGE)


if __name__ == "__main__":
    sys.exit(main())
