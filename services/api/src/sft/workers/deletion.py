"""The deletion lifecycle job, one run (`sft.service.lifecycle`, #181): the module the chart's
CronJob runs. `python -m sft.workers.jobs deletion` is the same run."""

from __future__ import annotations

import sys

from sft.service.lifecycle import Job
from sft.workers.jobs import main as run


def main() -> int:
    return run([], job=Job.DELETION)


if __name__ == "__main__":
    sys.exit(main())
