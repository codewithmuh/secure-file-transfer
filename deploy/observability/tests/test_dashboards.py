"""The Grafana dashboards as code (NFR-17, #244): every dashboard parses, is provisioned read-only, and queries only
metrics that exist.

A dashboard may query a metric only if it is in the metrics catalogue (docs/operations/metrics.md, #242), defined by
the service's code, one of the AWS series the CloudWatch exporter is configured to make, or a series a recording rule in
deploy/alerts makes. Run from the repository root:
`uv run --project services/api --locked pytest deploy/observability/tests`.
"""

from __future__ import annotations

import copy
import json
import re
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[3]
CHARTS = ROOT / "deploy" / "observability" / "charts"
DASHBOARDS = CHARTS / "grafana" / "dashboards"
CATALOGUE = ROOT / "docs" / "operations" / "metrics.md"
SOURCE = ROOT / "services" / "api" / "src"

# The dashboards #244 asks for, by uid.
EXPECTED = {
    "sft-slo-overview",
    "sft-journeys",
    "sft-scanning-dlp",
    "sft-data-replication",
    "sft-lifecycle-jobs",
}

METRIC = re.compile(r"[a-zA-Z_:][a-zA-Z0-9_:]*")
# PromQL words that aren't metrics: modifiers, set operators and literals.
KEYWORDS = {
    "by",
    "without",
    "on",
    "ignoring",
    "group_left",
    "group_right",
    "bool",
    "offset",
    "and",
    "or",
    "unless",
    "inf",
    "nan",
    "Inf",
    "NaN",
}


def metric_names(expr: str) -> set[str]:
    """The metric names an expression selects: identifiers that aren't functions, keywords, labels or numbers."""
    s = re.sub(
        r'"(?:[^"\\]|\\.)*"', '""', expr
    )  # string literals, label values among them
    s = re.sub(r"'(?:[^'\\]|\\.)*'", "''", s)
    s = re.sub(r"\{[^}]*\}", "", s)  # label matchers
    s = re.sub(r"\[[^\]]*\]", "", s)  # ranges and subqueries
    s = re.sub(
        r"\b(by|without|on|ignoring|group_left|group_right)\s*\([^)]*\)", " ", s
    )  # label lists
    s = re.sub(r"\$\{?\w+\}?", " ", s)  # Grafana variables
    names = set()
    for match in METRIC.finditer(s):
        name = match.group(0)
        before = s[match.start() - 1] if match.start() else " "
        if before.isdigit() or before == ".":  # the e in 1e-9, the m in 5m
            continue
        if s[match.end() :].lstrip().startswith("("):  # a function or an aggregation
            continue
        if name not in KEYWORDS:
            names.add(name)
    return names


def base(name: str) -> str:
    """A series' metric family: without a histogram's or summary's suffix, and without a counter's _total."""
    name = re.sub(r"_(bucket|sum|count|created)$", "", name)
    return name.removesuffix("_total")


def _snake(text: str) -> str:
    return re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", text).lower()


def _safe(text: str) -> str:
    return re.sub(r"[^a-zA-Z0-9:_]", "_", text)


def recorded_series() -> set[str]:
    """The series the recording rules in deploy/alerts make, such as the SLOs' slo:error_budget_remaining:ratio_28d
    (docs/operations/slos.md 2): the SLO dashboard reads them, so its figures are the alerts' figures."""
    names = set()
    for path in sorted((ROOT / "deploy" / "alerts").glob("*.rules.yaml")):
        for group in yaml.safe_load(path.read_text())["groups"]:
            names.update(rule["record"] for rule in group["rules"] if "record" in rule)
    return names


def exporter_series() -> set[str]:
    """What the CloudWatch exporter names each configured metric: aws_<namespace>_<metric>_<statistic>, the
    namespace lower-cased and the metric and statistic in snake case (prometheus/cloudwatch_exporter)."""
    values = yaml.safe_load((CHARTS / "prometheus" / "values.yaml").read_text())
    names = set()
    for m in values["cloudwatchExporter"]["metrics"]:
        for stat in m["statistics"]:
            names.add(
                _safe(f"{m['namespace'].lower()}_{_snake(m['name'])}_{_snake(stat)}")
            )
    return names


def code_metrics() -> set[str]:
    """Every metric family the service defines with prometheus_client."""
    pattern = re.compile(
        r"\b(?:Counter|Gauge|Histogram|Summary)\(\s*\"([a-z_:][a-z0-9_:]*)\""
    )
    return {
        m.group(1)
        for path in SOURCE.rglob("*.py")
        for m in pattern.finditer(path.read_text())
    }


def catalogue() -> set[str]:
    """The catalogue's metric names: the first column of its tables, in backticks."""
    names = set()
    for line in CATALOGUE.read_text().splitlines():
        if line.startswith("|"):
            first = line.split("|")[1]
            names.update(re.findall(r"`([a-z_:][a-z0-9_:]*)", first))
    return names


def allowed() -> set[str]:
    return {
        base(n)
        for n in catalogue() | code_metrics() | exporter_series() | recorded_series()
    }


def dashboards() -> dict[str, dict[str, Any]]:
    return {
        path.name: json.loads(path.read_text())
        for path in sorted(DASHBOARDS.glob("*.json"))
    }


def panels(board: dict[str, Any]) -> list[dict[str, Any]]:
    out = []
    for panel in board["panels"]:
        out.append(panel)
        out.extend(panel.get("panels", []))
    return out


def unknown_metrics(board: dict[str, Any], known: set[str]) -> list[tuple[str, str]]:
    """(panel title, metric) for each metric a panel queries that isn't known."""
    found = []
    for panel in panels(board):
        for target in panel.get("targets", []):
            for name in sorted(metric_names(target["expr"])):
                if base(name) not in known:
                    found.append((panel["title"], name))
    return found


def provisioned_datasources() -> set[str]:
    text = (CHARTS / "grafana" / "templates" / "config.yaml").read_text()
    return set(re.findall(r"^\s+uid: ([a-z]+)$", text, re.MULTILINE))


def test_metric_names_are_read_from_promql() -> None:
    expr = (
        'histogram_quantile(0.95, sum by (le, route) (rate(http_request_duration_seconds_bucket{route!~".*/x"}[5m])))'
        " / clamp_min(sum(rate(dlp_inspector_failures_total[10m])) + up offset 5m, 1e-9) and on (job) vector(1)"
    )
    assert metric_names(expr) == {
        "http_request_duration_seconds_bucket",
        "dlp_inspector_failures_total",
        "up",
    }
    assert metric_names(
        'time() - max by (job) (lifecycle_job_last_success_timestamp_seconds{job="purge"})'
    ) == {"lifecycle_job_last_success_timestamp_seconds"}
    assert (
        base("http_request_duration_seconds_bucket") == "http_request_duration_seconds"
    )
    assert base("emails_sent_total") == base("emails_sent") == "emails_sent"


def test_the_exporter_names_follow_its_own_rule() -> None:
    """The names deploy/alerts/scanning.rules.yaml already relies on (ADR-0009)."""
    series = exporter_series()
    assert "aws_sqs_approximate_number_of_messages_visible_maximum" in series
    assert "aws_rds_aurora_global_dbreplication_lag_maximum" in series
    assert "aws_applicationelb_httpcode_elb_5_xx_count_sum" in series


def test_every_dashboard_asked_for_is_there_and_parses() -> None:
    boards = dashboards()
    assert {b["uid"] for b in boards.values()} == EXPECTED
    for name, board in boards.items():
        assert name == f"{board['uid']}.json", name
        assert board["title"] and board["description"], name
        assert board["editable"] is False, name  # provisioned read-only (ADR-0009)
        ids = [p["id"] for p in panels(board)]
        assert len(ids) == len(set(ids)), name
    titles = [b["title"] for b in boards.values()]
    assert len(titles) == len(set(titles))


def test_every_panel_queries_a_provisioned_data_source() -> None:
    sources = provisioned_datasources()
    assert {"prometheus", "loki", "tempo", "alertmanager"} <= sources
    for name, board in dashboards().items():
        for panel in panels(board):
            if panel["type"] == "row":
                continue
            assert panel["datasource"]["uid"] in sources, (name, panel["title"])
            assert panel["targets"], (name, panel["title"])
            for target in panel["targets"]:
                assert target["datasource"]["uid"] in sources, (name, panel["title"])
                expr = target["expr"]
                for opening, closing in ("()", "[]", "{}"):
                    assert expr.count(opening) == expr.count(closing), (
                        name,
                        panel["title"],
                        expr,
                    )
            grid = panel["gridPos"]
            assert grid["x"] + grid["w"] <= 24, (name, panel["title"])


def test_dashboards_query_only_catalogued_metrics() -> None:
    known = allowed()
    for name, board in dashboards().items():
        assert unknown_metrics(board, known) == [], name


def test_a_panel_with_an_unknown_metric_fails() -> None:
    board = copy.deepcopy(dashboards()["sft-slo-overview.json"])
    planted = copy.deepcopy(next(p for p in panels(board) if p["type"] != "row"))
    planted["title"] = "Planted"
    planted["targets"] = [
        {
            "refId": "A",
            "datasource": {"uid": "prometheus"},
            "expr": "sum(rate(sft_not_a_metric_total[5m]))",
        }
    ]
    board["panels"].append(planted)
    assert unknown_metrics(board, allowed()) == [("Planted", "sft_not_a_metric_total")]
