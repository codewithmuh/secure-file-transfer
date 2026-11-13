"""Every alert and every alarm links to a runbook that exists (NFR-17, #245).

Reads the Prometheus rules (deploy/alerts/*.rules.yaml), and the CloudWatch alarms and EventBridge alerts in Terraform
(infra/**/*.tf), as files, so it needs neither Prometheus nor AWS. Also checks that each alert has the labels
Alertmanager routes on and a promtool test that makes it fire (deploy/alerts/tests), and that the runbook index lists
it. The last tests plant a
bad alert and a bad alarm to show that the checks catch them.

Run from the repository root: `uv run --project services/api --locked pytest deploy/tests` (`make deploy-check`).
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
ALERTS = ROOT / "deploy" / "alerts"
RUNBOOKS = ROOT / "docs" / "runbooks"
INFRA = ROOT / "infra"

RUNBOOK_URL = re.compile(
    r"https://github\.com/codewithmuh/secure-file-transfer/blob/main/docs/runbooks/([a-z0-9-]+)\.md"
)
# Alertmanager routes on these (deploy/alerts/alertmanager.yaml). Only the Watchdog feeds the heartbeat.
SEVERITIES = {"page", "ticket"}
HEARTBEAT = {"Watchdog": "heartbeat"}
ALARM_BLOCK = re.compile(
    r'^resource\s+"(aws_cloudwatch_metric_alarm|aws_cloudwatch_composite_alarm)"\s+"([^"]+)"\s*\{',
    re.MULTILINE,
)


def alerts(directory: Path) -> list[tuple[str, dict[str, Any]]]:
    """Every alerting rule in the directory's *.rules.yaml files, with the file it is in."""
    found = []
    for path in sorted(directory.glob("*.rules.yaml")):
        document = yaml.safe_load(path.read_text()) or {}
        for group in document.get("groups", []):
            for rule in group.get("rules", []):
                if "alert" in rule:
                    found.append((path.name, rule))
    return found


def runbook_problem(url: object, runbooks: Path) -> str | None:
    """Why a runbook URL is wrong, or None when it names a runbook that exists."""
    if not isinstance(url, str):
        return "no runbook_url"
    match = RUNBOOK_URL.fullmatch(url)
    if match is None:
        return f"runbook_url {url!r} isn't a runbook in docs/runbooks/"
    if not (runbooks / f"{match.group(1)}.md").is_file():
        return f"runbook docs/runbooks/{match.group(1)}.md doesn't exist"
    return None


def alert_problems(directory: Path, runbooks: Path) -> list[str]:
    """What is wrong with the alerting rules: a missing runbook, summary or severity."""
    problems = []
    for file, rule in alerts(directory):
        name = rule["alert"]
        annotations = rule.get("annotations") or {}
        severity = (rule.get("labels") or {}).get("severity")
        if (
            problem := runbook_problem(annotations.get("runbook_url"), runbooks)
        ) is not None:
            problems.append(f"{file}: {name}: {problem}")
        if not annotations.get("summary"):
            problems.append(f"{file}: {name}: no summary")
        if severity not in SEVERITIES and HEARTBEAT.get(name) != severity:
            problems.append(
                f"{file}: {name}: severity {severity!r} isn't page or ticket"
            )
    return problems


def alarm_blocks(root: Path) -> list[tuple[Path, str, str]]:
    """Every CloudWatch alarm resource block in the .tf files under root: its file, address and text."""
    blocks = []
    for path in sorted(root.rglob("*.tf")):
        if ".terraform" in path.parts:
            continue
        text = path.read_text()
        for match in ALARM_BLOCK.finditer(text):
            depth, end = 0, match.end() - 1
            for end in range(match.end() - 1, len(text)):
                depth += {"{": 1, "}": -1}.get(text[end], 0)
                if depth == 0:
                    break
            blocks.append(
                (
                    path,
                    f"{match.group(1)}.{match.group(2)}",
                    text[match.start() : end + 1],
                )
            )
    return blocks


def alarm_problems(root: Path, runbooks: Path) -> list[str]:
    """Every alarm's description names exactly one runbook, literally, and it exists (#246)."""
    problems = []
    for path, address, block in alarm_blocks(root):
        description = re.search(r"^\s*alarm_description\s*=(.*)$", block, re.MULTILINE)
        urls = RUNBOOK_URL.findall(description.group(1)) if description else []
        where = f"{path.relative_to(root)}: {address}"
        if len(urls) != 1:
            problems.append(
                f"{where}: alarm_description must name one runbook URL, found {len(urls)}"
            )
            continue
        if not (runbooks / f"{urls[0]}.md").is_file():
            problems.append(
                f"{where}: runbook docs/runbooks/{urls[0]}.md doesn't exist"
            )
    return problems


def test_every_alert_links_to_a_runbook_that_exists() -> None:
    assert alerts(ALERTS), "no alerting rules found"
    assert alert_problems(ALERTS, RUNBOOKS) == []


def test_every_cloudwatch_alarm_links_to_a_runbook_that_exists() -> None:
    assert alarm_blocks(INFRA), "no CloudWatch alarms found"
    assert alarm_problems(INFRA, RUNBOOKS) == []


def test_every_alert_rule_has_a_promtool_case_that_fires_it() -> None:
    """Each rule, told apart by its alert name and labels, fires in at least one case (#245: a case per alert)."""
    fired: list[tuple[str, dict[str, str]]] = []
    for path in ALERTS.glob("tests/*.test.yaml"):
        for test in yaml.safe_load(path.read_text()).get("tests", []):
            for case in test.get("alert_rule_test", []):
                for expected in case.get("exp_alerts") or []:
                    fired.append((case["alertname"], expected.get("exp_labels") or {}))
    untested = [
        f"{file}: {rule['alert']} {rule.get('labels')}"
        for file, rule in alerts(ALERTS)
        if not any(
            name == rule["alert"]
            and (rule.get("labels") or {}).items() <= labels.items()
            for name, labels in fired
        )
    ]
    assert untested == []


def test_the_runbook_index_lists_every_alert_and_alarm_runbook() -> None:
    index = (RUNBOOKS / "README.md").read_text()
    missing = {f"`{rule['alert']}`" for _, rule in alerts(ALERTS)} - set(
        re.findall(r"`[A-Za-z]+`", index)
    )
    for _, _, block in alarm_blocks(INFRA):
        for runbook in RUNBOOK_URL.findall(block):
            if f"({runbook}.md)" not in index:
                missing.add(f"{runbook}.md")
    assert not missing, sorted(missing)


def test_every_eventbridge_alert_links_to_a_runbook_that_exists_and_is_listed() -> None:
    """The security alerts that are EventBridge rules, not alarms (#232, #256, #263, #277): every runbook a file with
    an EventBridge target names, as a URL or, in the alarms module, as a rule's runbook, exists and is in the index."""
    index = (RUNBOOKS / "README.md").read_text()
    named: list[tuple[str, str]] = []
    for path in sorted(INFRA.rglob("*.tf")):
        if ".terraform" in path.parts:
            continue
        text = path.read_text()
        if 'resource "aws_cloudwatch_event_target"' not in text:
            continue
        where = str(path.relative_to(INFRA))
        named += [(where, runbook) for runbook in RUNBOOK_URL.findall(text)]
        named += [
            (where, runbook)
            for runbook in re.findall(
                r'^\s*runbook\s*=\s*"([a-z0-9-]+)"', text, re.MULTILINE
            )
        ]
    assert ("organization/scp-alerts.tf", "scp-change") in named
    problems = [
        f"{where}: docs/runbooks/{runbook}.md doesn't exist"
        for where, runbook in named
        if not (RUNBOOKS / f"{runbook}.md").is_file()
    ] + [
        f"{where}: docs/runbooks/README.md doesn't list {runbook}.md"
        for where, runbook in named
        if f"({runbook}.md)" not in index
    ]
    assert problems == []


# The planted alert and alarm of #245's acceptance criteria: the checks above must catch each.
PLANTED_RULES = """
groups:
  - name: planted
    rules:
      - alert: NoRunbook
        expr: vector(1)
        labels: {severity: page}
        annotations: {summary: An alert without a runbook.}
      - alert: MissingRunbook
        expr: vector(1)
        labels: {severity: ticket}
        annotations:
          summary: An alert whose runbook doesn't exist.
          runbook_url: https://github.com/codewithmuh/secure-file-transfer/blob/main/docs/runbooks/no-such-runbook.md
      - alert: NotARunbook
        expr: vector(1)
        labels: {severity: info}
        annotations:
          summary: An alert that links elsewhere, with a severity nothing routes.
          runbook_url: https://example.com/runbook.md
"""

PLANTED_ALARMS = """
resource "aws_cloudwatch_metric_alarm" "no_runbook" {
  alarm_name        = "sft-dev-apne1-planted"
  alarm_description = "An alarm without a runbook. Severity: page."
  dimensions        = { QueueName = "q" }
}

resource "aws_cloudwatch_metric_alarm" "missing_runbook" {
  alarm_name        = "sft-dev-apne1-planted-2"
  alarm_description = "Severity: ticket. Runbook: https://github.com/codewithmuh/secure-file-transfer/blob/main/docs/runbooks/no-such-runbook.md"
}
"""


@pytest.fixture
def planted(tmp_path: Path) -> Path:
    (tmp_path / "alerts").mkdir()
    (tmp_path / "alerts" / "planted.rules.yaml").write_text(PLANTED_RULES)
    (tmp_path / "infra").mkdir()
    (tmp_path / "infra" / "planted.tf").write_text(PLANTED_ALARMS)
    (tmp_path / "runbooks").mkdir()
    return tmp_path


def test_a_planted_alert_without_a_runbook_fails(planted: Path) -> None:
    problems = alert_problems(planted / "alerts", planted / "runbooks")
    assert problems == [
        "planted.rules.yaml: NoRunbook: no runbook_url",
        "planted.rules.yaml: MissingRunbook: runbook docs/runbooks/no-such-runbook.md doesn't exist",
        "planted.rules.yaml: NotARunbook: runbook_url 'https://example.com/runbook.md' isn't a runbook in docs/runbooks/",
        "planted.rules.yaml: NotARunbook: severity 'info' isn't page or ticket",
    ]
    # Once the runbook exists, its alert passes.
    (planted / "runbooks" / "no-such-runbook.md").write_text("# Runbook\n")
    assert not any(
        "MissingRunbook" in p
        for p in alert_problems(planted / "alerts", planted / "runbooks")
    )


def test_a_planted_alarm_without_a_runbook_fails(planted: Path) -> None:
    assert alarm_problems(planted / "infra", planted / "runbooks") == [
        "planted.tf: aws_cloudwatch_metric_alarm.no_runbook: alarm_description must name one runbook URL, found 0",
        "planted.tf: aws_cloudwatch_metric_alarm.missing_runbook: runbook docs/runbooks/no-such-runbook.md doesn't exist",
    ]
