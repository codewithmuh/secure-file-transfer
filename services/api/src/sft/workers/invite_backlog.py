"""The invitation backlog's entry point (#193): `python -m sft.workers.invite_backlog`.

The same as `python -m sft.workers.notify invite-backlog`, as a module of its own, because the
chart runs each entry point as `python -m <module>` (deploy/charts/sft, the `invite-backlog`
CronJob, always suspended and run by hand once the user pool exists).
"""

from __future__ import annotations

import sys

from sft.workers import notify


def main() -> int:
    return notify.main(["invite-backlog"])


if __name__ == "__main__":
    sys.exit(main())
