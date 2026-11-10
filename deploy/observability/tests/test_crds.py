"""The Prometheus Operator's CRDs that the upgrade procedure applies (#264, docs/operations/observability.md section 11).

Helm installs a chart's CRDs only on its first install, so a kube-prometheus-stack bump in cluster-bootstrap would run
the new operator against the old CRDs. The bump vendors the new chart's CRD bundle into deploy/observability/crds,
and the procedure server-side applies it before Terraform upgrades the operator. These tests check, offline, that the
bundle is the one for the chart and operator images.tf pins, and that it serves every kind the stack renders;
deploy/observability/crds/check.sh, run by deploy/check.sh, checks it byte for byte against the pinned chart itself.
"""

from __future__ import annotations

import bz2
import re
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[3]
CRDS = ROOT / "deploy" / "observability" / "crds"
IMAGES_TF = ROOT / "infra" / "modules" / "cluster-bootstrap" / "images.tf"
GROUP = "monitoring.coreos.com"
# The CRDs hold `=` as a plain value, which the safe loader can't construct; the base loader reads everything as text.
LOADER = getattr(yaml, "CBaseLoader", yaml.BaseLoader)

Manifest = dict[str, Any]
Rendered = dict[tuple[str, str, str], list[Manifest]]


def pins(images_tf: str) -> dict[str, str]:
    """What cluster-bootstrap pins: the chart's version and the operator's and config reloader's image tags."""

    def field(block: str, name: str) -> str:
        match = re.search(
            rf"\b{block} = \{{[^}}]*?\b{name}\s+= \"([^\"]+)\"", images_tf
        )
        assert match, (block, name)
        return match.group(1)

    return {
        "chart": field("kube_prometheus_stack", "version"),
        "operator": field("prometheus_operator", "tag"),
        "reloader": field("prometheus_config_reloader", "tag"),
    }


def crds(bundle: Path) -> list[Manifest]:
    text = bz2.decompress(bundle.read_bytes()).decode()
    return [d for d in yaml.load_all(text, Loader=LOADER) if d]


def mismatches(images_tf: str, bundles: list[Path]) -> list[str]:
    """Every way the vendored bundles differ from what images.tf pins; empty when they match."""
    pinned = pins(images_tf)
    expected = f"kube-prometheus-stack-{pinned['chart']}.crds.bz2"
    if [b.name for b in bundles] != [expected]:
        return [
            f"expected only {expected} in {CRDS}, found {[b.name for b in bundles]}"
        ]
    found = []
    if pinned["reloader"] != pinned["operator"]:
        found.append(
            f"the config reloader {pinned['reloader']} isn't the operator's {pinned['operator']}"
        )
    for crd in crds(bundles[0]):
        name = crd["metadata"]["name"]
        version = crd["metadata"]["annotations"].get("operator.prometheus.io/version")
        if f"v{version}" != pinned["operator"]:
            found.append(
                f"{name} is for operator {version}, images.tf pins {pinned['operator']}"
            )
        if crd["spec"]["group"] != GROUP:
            found.append(f"{name} is not in {GROUP}")
    return found


def test_the_vendored_crds_are_the_pinned_chart_and_operator() -> None:
    assert mismatches(IMAGES_TF.read_text(), sorted(CRDS.glob("*.crds.bz2"))) == []


def test_a_bump_without_its_crds_fails() -> None:
    """The check fails on a mismatch: the chart bumped and its CRDs not vendored, or the operator bumped alone."""
    text = IMAGES_TF.read_text()
    bundles = sorted(CRDS.glob("*.crds.bz2"))
    chart = pins(text)["chart"]
    bumped_chart = text.replace(f'"{chart}"', '"999.0.0"')
    assert mismatches(bumped_chart, bundles) == [
        f"expected only kube-prometheus-stack-999.0.0.crds.bz2 in {CRDS}, found {[b.name for b in bundles]}"
    ]
    operator = pins(text)["operator"]
    bumped_operator = text.replace(f'"{operator}"', '"v999.0.0"')
    found = mismatches(bumped_operator, bundles)
    assert len(found) == len(crds(bundles[0])) and all("v999.0.0" in f for f in found)


def test_the_crds_serve_every_kind_the_stack_renders(rendered: Rendered) -> None:
    """Each Prometheus Operator object the observability charts render has its kind and version in the bundle."""
    (bundle,) = sorted(CRDS.glob("*.crds.bz2"))
    served = {
        (crd["spec"]["names"]["kind"], f"{GROUP}/{version['name']}")
        for crd in crds(bundle)
        for version in crd["spec"]["versions"]
        if version["served"] == "true"
    }
    used = {
        (obj["kind"], obj["apiVersion"])
        for (_, _, part), objects in rendered.items()
        if part.startswith("observability-")
        for obj in objects
        if obj["apiVersion"].startswith(f"{GROUP}/")
    }
    assert used, "the stack renders no Prometheus Operator objects"
    assert used <= served, sorted(used - served)
