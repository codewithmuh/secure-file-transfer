#!/usr/bin/env python3
"""Print the test files of one CI shard: `pytest-shard.py <shard> <shards>` (shards are numbered from 1).

ci.yml splits services/api's tests across parallel jobs, each with its own PostgreSQL, ElasticMQ, Valkey, S3Mock and
clamd, so the suite runs in a fraction of the time one job takes. The split is deterministic and covers every
`tests/test_*.py` file exactly once: files are weighed by size, the heaviest placed first, each in the lightest shard
so far. Size is a rough stand-in for run time; the shards don't need to be equal, only close.
"""

import sys
from pathlib import Path

TESTS = Path(__file__).resolve().parents[2] / "services" / "api" / "tests"


def shards(count: int) -> list[list[str]]:
    files = sorted(
        TESTS.glob("test_*.py"), key=lambda path: (-path.stat().st_size, path.name)
    )
    bins: list[tuple[int, list[str]]] = [(0, []) for _ in range(count)]
    for path in files:
        index = min(range(count), key=lambda i: (bins[i][0], i))
        weight, names = bins[index]
        bins[index] = (weight + path.stat().st_size, [*names, f"tests/{path.name}"])
    return [sorted(names) for _, names in bins]


def main() -> int:
    shard, count = int(sys.argv[1]), int(sys.argv[2])
    if not 1 <= shard <= count:
        print(f"shard {shard} is outside 1..{count}", file=sys.stderr)
        return 2
    print(" ".join(shards(count)[shard - 1]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
