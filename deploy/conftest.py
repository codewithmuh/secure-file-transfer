"""What deploy/tests and deploy/observability/tests share: every cluster rendered once, by deploy/render.sh (#186).

CI's deploy job renders into one directory with deploy/check.sh, runs kubeconform, Kyverno and Trivy on it, and passes
it to pytest as SFT_RENDERED, so the tests read the same manifests instead of rendering every cluster again. Without
SFT_RENDERED the fixture renders into a temporary directory (helm on PATH). Run from the repository root, so that
pytest finds this file: `uv run --project services/api --locked pytest deploy/tests deploy/observability/tests`.
"""

from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path
from typing import Any

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]

Manifest = dict[str, Any]
Rendered = dict[tuple[str, str, str], list[Manifest]]


@pytest.fixture(scope="session")
def rendered(tmp_path_factory: pytest.TempPathFactory) -> Rendered:
    """(env, region, part) -> the objects in render.sh's `<env>-<region>-<part>.yaml`, for every file it writes."""
    given = os.environ.get("SFT_RENDERED")
    if given:
        out = Path(given)
    else:
        out = tmp_path_factory.mktemp("rendered")
        subprocess.run(
            [str(ROOT / "deploy" / "render.sh"), str(out)],
            check=True,
            capture_output=True,
        )
    result: Rendered = {}
    for path in sorted(out.glob("*.yaml")):
        match = re.fullmatch(
            r"(dev|staging|prod)-(ap-northeast-[13])-(.+)\.yaml", path.name
        )
        assert match, path.name
        env, region, part = match.groups()
        result[(env, region, part)] = [
            d for d in yaml.safe_load_all(path.read_text()) if d
        ]
    # A wrong or empty SFT_RENDERED fails here, not as a missing key in every test.
    assert result, f"nothing rendered in {out}"
    return result
