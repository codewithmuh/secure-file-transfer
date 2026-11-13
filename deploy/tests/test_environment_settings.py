"""Every workload starts with its settings in every cluster: dev, staging and prod, Tokyo and Osaka (#247).

test_rendered.py checks that each required setting is in the pod spec. This goes further: it loads each container's
settings class from exactly the environment its pod spec gives it, the way the process does at startup
(`load_settings`), so a cross-field rule (API_KEY_ENVIRONMENT outside tests, TRUSTED_PROXIES behind the load balancer,
IAM-authenticated URLs) fails here rather than in a crash-looping pod after a promotion. It also checks the settings
that the code leaves optional but that staging and prod need because they have Osaka (architecture 3.2), and that each
cluster's values agree with its environment. Secret values come from Secrets Manager at run time and are never in a
manifest: a `secretKeyRef` is filled with a stand-in here.

Run from the repository root: `uv run --project services/api --locked pytest deploy/tests` (`make deploy-check`).
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
import yaml
from pydantic import ValidationError
from pydantic_settings import BaseSettings
from sft.core.settings import (
    ArchiveJobSettings,
    BootstrapSettings,
    FieldKeySettings,
    InspectorSettings,
    JobSettings,
    KeyRotationSettings,
    MigrationSettings,
    NotifySettings,
    OperatorSettings,
    RecoverySettings,
    RelaySettings,
    ScanSettings,
    Settings,
)
from sft.probe.settings import ProbeSettings

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "services" / "api" / "src"
CLUSTERS = [
    ("dev", "ap-northeast-1"),
    ("staging", "ap-northeast-1"),
    ("staging", "ap-northeast-3"),
    ("prod", "ap-northeast-1"),
    ("prod", "ap-northeast-3"),
]
OSAKA = "ap-northeast-3"

# Every entry point the chart runs, and the settings it loads at startup. A module that exists in the source but not
# here fails test_every_entry_point_has_its_settings_class, so a new workload can't skip these checks.
SETTINGS: dict[str, type[BaseSettings]] = {
    "sft.api": Settings,
    "sft.api.operator": OperatorSettings,
    "sft.workers.relay": RelaySettings,
    "sft.data.migrate": MigrationSettings,
    "sft.data.bootstrap": BootstrapSettings,  # #278, always suspended, run by hand once per environment
    "sft.dlp.inspector": InspectorSettings,
    "sft.workers.scan": ScanSettings,
    "sft.workers.notify": NotifySettings,
    "sft.workers.invite_backlog": NotifySettings,
    "sft.workers.standby_enrolment": NotifySettings,  # #258, as the notification worker
    "sft.workers.recovery": RecoverySettings,  # #258, always suspended, run by the runbooks
    "sft.workers.key_rotation": KeyRotationSettings,
    "sft.workers.field_keys": FieldKeySettings,
    "sft.workers.expiry": JobSettings,
    "sft.workers.deletion": JobSettings,
    "sft.workers.reconciliation": JobSettings,
    "sft.workers.storage_audit": JobSettings,
    "sft.workers.cleanup": JobSettings,
    "sft.workers.purge": JobSettings,
    "sft.workers.audit_partitions": JobSettings,
    "sft.workers.audit_archive": ArchiveJobSettings,
    "sft.probe": ProbeSettings,
}

# What staging and prod need beyond the code's defaults, by entry point: both Regions' audit archive for the
# security-critical records (architecture 5.2) and the files buckets' Osaka replicas for the lifecycle jobs (NFR-8).
OUTSIDE_DEV = {
    "sft.api": {"AUDIT_ARCHIVE_OSAKA_BUCKET"},
    "sft.workers.reconciliation": {
        "AUDIT_ARCHIVE_OSAKA_BUCKET",
        "S3_REPLICA_REGION",
        "S3_REPLICA_FILES_BUCKET",
        "S3_REPLICA_LARGE_FILES_BUCKET",
    },
    "sft.workers.deletion": {
        "S3_REPLICA_REGION",
        "S3_REPLICA_FILES_BUCKET",
        "S3_REPLICA_LARGE_FILES_BUCKET",
    },
    "sft.workers.storage_audit": {
        "S3_REPLICA_REGION",
        "S3_REPLICA_FILES_BUCKET",
        "S3_REPLICA_LARGE_FILES_BUCKET",
    },
}

# How each environment names itself in the settings that carry it.
API_KEY_ENVIRONMENT = {"dev": "dev", "staging": "stg", "prod": "prd"}

Manifest = dict[str, Any]


@pytest.fixture(scope="module")
def containers(
    rendered: dict[tuple[str, str, str], list[Manifest]],
) -> list[tuple[str, str, str, str, Manifest]]:
    """(env, region, workload, module, container) for every container of ours in every cluster, as rendered
    (deploy/conftest.py)."""
    found = []
    for env, region in CLUSTERS:
        for part in ("application", "operator"):
            for obj in rendered[(env, region, part)]:
                if obj["kind"] not in {"Deployment", "CronJob", "Job"}:
                    continue
                spec = (
                    obj["spec"]["jobTemplate"]["spec"]["template"]["spec"]
                    if obj["kind"] == "CronJob"
                    else obj["spec"]["template"]["spec"]
                )
                for container in spec["containers"]:
                    command = container.get("command", [])
                    if command[:2] == ["python", "-m"] and command[2].startswith(
                        "sft."
                    ):
                        found.append(
                            (
                                env,
                                region,
                                obj["metadata"]["name"],
                                command[2],
                                container,
                            )
                        )
    return found


def environment_of(container: Manifest) -> dict[str, str]:
    """The container's environment as the process sees it, with a stand-in for each value from a Secret."""
    result = {}
    for variable in container.get("env", []):
        if "value" in variable:
            result[variable["name"]] = str(variable["value"])
        else:
            assert "secretKeyRef" in variable["valueFrom"], variable["name"]
            result[variable["name"]] = "test-only-stand-in"
    return result


def module_exists(module: str) -> bool:
    path = SOURCE.joinpath(*module.split("."))
    return path.with_suffix(".py").is_file() or (path / "__main__.py").is_file()


def ours(
    containers: list[tuple[str, str, str, str, Manifest]],
) -> Iterator[tuple[str, str, str, str, Manifest]]:
    for entry in containers:
        if entry[3] in SETTINGS:
            yield entry


def test_every_entry_point_has_its_settings_class(
    containers: list[tuple[str, str, str, str, Manifest]],
) -> None:
    """A module the chart runs is either checked here or not written yet (its issue adds it to SETTINGS)."""
    unchecked = {
        module
        for _, _, _, module, _ in containers
        if module not in SETTINGS and module_exists(module)
    }
    assert not unchecked, f"add these entry points to SETTINGS: {sorted(unchecked)}"
    assert {module for _, _, _, module, _ in containers} >= set(SETTINGS)


def test_every_workload_loads_its_settings_in_every_cluster(
    containers: list[tuple[str, str, str, str, Manifest]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    failures = []
    for env, region, workload, module, container in ours(containers):
        with monkeypatch.context() as patch:
            for name in list(os.environ):
                patch.delenv(name)
            for name, value in environment_of(container).items():
                patch.setenv(name, value)
            try:
                SETTINGS[module](_env_file=None)
            except ValidationError as exc:
                fields = sorted(
                    {
                        ".".join(str(p) for p in e["loc"]) or e["msg"]
                        for e in exc.errors()
                    }
                )
                failures.append(f"{env} {region} {workload} ({module}): {fields}")
    assert not failures, "\n".join(failures)


def test_staging_and_prod_set_what_osaka_needs(
    containers: list[tuple[str, str, str, str, Manifest]],
) -> None:
    missing = []
    for env, region, workload, module, container in ours(containers):
        settings = environment_of(container)
        needed = OUTSIDE_DEV.get(module, set()) if env != "dev" else set()
        if lacking := sorted(name for name in needed if not settings.get(name)):
            missing.append(f"{env} {region} {workload}: {lacking}")
        # dev has no Osaka: a replica or an Osaka archive there would point at nothing.
        present = sorted(
            name for name in OUTSIDE_DEV.get(module, set()) if settings.get(name)
        )
        if env == "dev" and present:
            missing.append(
                f"{env} {region} {workload} sets {present}, which dev doesn't have"
            )
    assert not missing, "\n".join(missing)


def test_each_cluster_names_its_own_environment_and_region(
    containers: list[tuple[str, str, str, str, Manifest]],
) -> None:
    wrong = []
    for env, region, workload, module, container in ours(containers):
        settings = environment_of(container)
        expected = {
            "ENVIRONMENT": env,
            "OPERATOR_ENVIRONMENT": env,
            "API_KEY_ENVIRONMENT": API_KEY_ENVIRONMENT[env],
            "AWS_REGION": region,
        }
        for name, value in expected.items():
            if name in settings and settings[name] != value:
                wrong.append(
                    f"{env} {region} {workload}: {name}={settings[name]!r}, expected {value!r}"
                )
        if module == "sft.api" and "API_KEY_ENVIRONMENT" not in settings:
            wrong.append(f"{env} {region} {workload}: no API_KEY_ENVIRONMENT")
    assert not wrong, "\n".join(wrong)


@pytest.mark.parametrize("env", ["staging", "prod"])
def test_osaka_mirrors_tokyo_except_the_pilot_light_and_network(env: str) -> None:
    """Architecture 3.2: a failover runs in Osaka what Tokyo runs, so both values files size the same workloads."""
    tokyo, osaka = (
        yaml.safe_load(
            (
                ROOT / "deploy" / "environments" / env / region / "values.yaml"
            ).read_text()
        )
        for region in ("ap-northeast-1", OSAKA)
    )
    assert tokyo["pilotLight"] is False
    assert osaka["pilotLight"] is True
    # failover: Osaka's holdWorkers is the state its fencing commit starts from (ops/failover-values.sh).
    differ = {"pilotLight", "network", "image", "failover"}
    assert {k: v for k, v in tokyo.items() if k not in differ} == {
        k: v for k, v in osaka.items() if k not in differ
    }
    assert tokyo["image"] == osaka["image"], "both Regions run the same digest (NFR-18)"


def test_a_planted_missing_setting_fails(
    containers: list[tuple[str, str, str, str, Manifest]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """#247's acceptance: take a setting the API needs out of prod's pod spec, and loading fails on it."""
    _, _, _, module, container = next(
        c
        for c in containers
        if c[:2] == ("prod", "ap-northeast-1") and c[3] == "sft.api"
    )
    for dropped in ("DATABASE_URL", "TRUSTED_PROXIES", "API_KEY_ENVIRONMENT"):
        with monkeypatch.context() as patch:
            for name in list(os.environ):
                patch.delenv(name)
            for name, value in environment_of(container).items():
                if name != dropped:
                    patch.setenv(name, value)
            with pytest.raises(ValidationError):
                SETTINGS[module](_env_file=None)
