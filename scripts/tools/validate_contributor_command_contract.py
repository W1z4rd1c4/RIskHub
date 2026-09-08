#!/usr/bin/env python3
"""Validate the contributor façade and executable CI ownership contract."""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any

import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS_DIR = REPO_ROOT / ".github/workflows"
FACADE = REPO_ROOT / "scripts/riskhub.sh"
INSTALLER = REPO_ROOT / "scripts/install.sh"
MAKEFILE = REPO_ROOT / "scripts/Makefile"
SCRIPT_README = REPO_ROOT / "scripts/README.md"
DEVELOPMENT_README = REPO_ROOT / "docs/development/README.md"
CONTRIBUTING = REPO_ROOT / "CONTRIBUTING.md"
CONTRACT_DOC = REPO_ROOT / "docs/development/CONTRIBUTOR_COMMANDS.md"
CI_CONTRACT = REPO_ROOT / "docs/development/ci-gate-contract.json"

EXPECTED_DELEGATES = {
    "setup": "exec ./scripts/install.sh doctor --mode dev --repair",
    "dev": 'exec ./scripts/install.sh dev "$@"',
    "lint": "exec make --no-print-directory -f scripts/Makefile lint lint-types",
    "test": "exec make --no-print-directory -f scripts/Makefile test",
    "e2e": "exec make --no-print-directory -f scripts/Makefile test-e2e",
    "release-check": (
        "exec make --no-print-directory -f scripts/Makefile release-parity-audit"
    ),
    "clean": "exec make --no-print-directory -f scripts/Makefile clean",
}

EXPECTED_MAKE_TARGETS = {
    "clean",
    "lint",
    "lint-types",
    "release-parity-audit",
    "test",
    "test-e2e",
}

EXPECTED_REQUIRED_CHECKS = {
    "Backend Quality",
    "Docker Onboarding Smoke",
    "Frontend + Repo Contracts",
    "PR Merge Result Build",
    "Playwright E2E Tests",
    "Public Repo Hygiene",
}

GOVERNED_WORKFLOWS = {
    ".github/workflows/backend-postgres.yml",
    ".github/workflows/e2e.yml",
    ".github/workflows/frontend-container-gate-contract.yml",
    ".github/workflows/identity-foundations.yml",
    ".github/workflows/lint.yml",
    ".github/workflows/maintenance-governance.yml",
    ".github/workflows/python-dev-lock-refresh.yml",
    ".github/workflows/release-parity-fast.yml",
    ".github/workflows/release-parity-pr.yml",
    ".github/workflows/release.yml",
    ".github/workflows/security.yml",
    ".github/workflows/startup-smoke-pr.yml",
    ".github/workflows/startup-smoke.yml",
}

EVENT_FILTER_KEYS = (
    "branches",
    "branches-ignore",
    "tags",
    "tags-ignore",
    "paths",
    "paths-ignore",
)


def _declared_make_targets() -> set[str]:
    targets: set[str] = set()
    for raw_line in MAKEFILE.read_text(encoding="utf-8").splitlines():
        if raw_line.startswith((" ", "\t", ".")):
            continue
        match = re.match(r"^([A-Za-z0-9_-]+)\s*:", raw_line)
        if match:
            targets.add(match.group(1))
    return targets


def _load_json_object(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"{path.relative_to(REPO_ROOT)} must contain an object")
    return payload


def _load_workflow(path: Path) -> dict[str, Any]:
    payload = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"{path.relative_to(REPO_ROOT)} must contain an object")
    return payload


def _workflow_on(workflow: dict[str, Any]) -> Any:
    if "on" in workflow:
        return workflow["on"]
    return workflow.get(True)


def _as_string_list(value: Any, *, field: str) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return list(value)
    raise ValueError(f"workflow event {field} must be a string or string list")


def _normalize_event(event_name: str, config: Any) -> dict[str, list[str]]:
    if event_name == "schedule":
        if not isinstance(config, list):
            raise ValueError("schedule must contain a list")
        crons: list[str] = []
        for item in config:
            if not isinstance(item, dict) or not isinstance(item.get("cron"), str):
                raise ValueError("schedule entries must contain cron strings")
            crons.append(item["cron"])
        return {"crons": crons}

    if event_name == "workflow_dispatch":
        if config is None:
            return {"inputs": []}
        if not isinstance(config, dict):
            raise ValueError("workflow_dispatch must be null or a mapping")
        inputs = config.get("inputs", {})
        if inputs is None:
            return {"inputs": []}
        if not isinstance(inputs, dict):
            raise ValueError("workflow_dispatch inputs must be a mapping")
        return {"inputs": [str(name) for name in inputs]}

    if config is None:
        return {}
    if not isinstance(config, dict):
        raise ValueError(f"{event_name} must be null or a mapping")

    normalized: dict[str, list[str]] = {}
    for key in EVENT_FILTER_KEYS:
        if key in config:
            normalized[key.replace("-", "_")] = _as_string_list(
                config[key],
                field=f"{event_name}.{key}",
            )
    return normalized


def _normalized_events(workflow: dict[str, Any]) -> dict[str, dict[str, list[str]]]:
    raw = _workflow_on(workflow)
    if isinstance(raw, str):
        return {raw: {}}
    if isinstance(raw, list):
        return {str(event): {} for event in raw}
    if not isinstance(raw, dict):
        raise ValueError("workflow `on` must be a string, list, or mapping")
    return {
        str(event_name): _normalize_event(str(event_name), config)
        for event_name, config in raw.items()
    }


def _normalize_expression(value: Any) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        return str(value)
    text = value.strip()
    if text.startswith("${{") and text.endswith("}}"):
        text = text[3:-2].strip()
    return re.sub(r"\s+", " ", text)


def _git_blob_sha(path: Path) -> str:
    data = path.read_bytes()
    prefix = f"blob {len(data)}\0".encode("utf-8")
    return hashlib.sha1(prefix + data).hexdigest()


def _validate_facade() -> list[str]:
    errors: list[str] = []

    if not FACADE.is_file():
        return ["missing scripts/riskhub.sh"]
    if not os.access(FACADE, os.X_OK):
        errors.append("scripts/riskhub.sh must be executable")
    if not INSTALLER.is_file() or not os.access(INSTALLER, os.X_OK):
        errors.append(
            "canonical scripts/install.sh delegate must exist and be executable"
        )
    if not MAKEFILE.is_file():
        errors.append("canonical scripts/Makefile delegate must exist")

    script_text = FACADE.read_text(encoding="utf-8")
    for command, delegate in EXPECTED_DELEGATES.items():
        if f"    {command})" not in script_text:
            errors.append(f"missing command case: {command}")
        if delegate not in script_text:
            errors.append(f"command {command} does not use its canonical delegate")

    exec_lines = [
        line.strip()
        for line in script_text.splitlines()
        if line.strip().startswith("exec ")
    ]
    expected_exec_lines = list(EXPECTED_DELEGATES.values())
    if sorted(exec_lines) != sorted(expected_exec_lines):
        errors.append(
            "façade contains an undocumented, missing, or duplicated executable path"
        )
    if len(exec_lines) != len(set(exec_lines)):
        errors.append("façade must not reuse one executable delegate for multiple commands")

    if MAKEFILE.is_file():
        missing_targets = EXPECTED_MAKE_TARGETS - _declared_make_targets()
        if missing_targets:
            errors.append(
                "façade delegates to missing Make targets: "
                + ", ".join(sorted(missing_targets))
            )

    syntax = subprocess.run(
        ["bash", "-n", str(FACADE)],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    if syntax.returncode != 0:
        errors.append(f"bash syntax validation failed: {syntax.stderr.strip()}")

    for required_help in (
        "Stop local dev/Compose, then run the full release-parity audit",
        "keep backend/venv",
    ):
        if required_help not in script_text:
            errors.append(f"façade help is missing side-effect disclosure: {required_help}")
    return errors


def _validate_workflow_contracts(
    contract: dict[str, Any],
) -> tuple[list[str], dict[str, dict[str, Any]]]:
    errors: list[str] = []
    raw_contracts = contract.get("workflow_contracts")
    if not isinstance(raw_contracts, dict):
        return ["CI gate contract must contain workflow_contracts"], {}
    if set(raw_contracts) != GOVERNED_WORKFLOWS:
        missing = GOVERNED_WORKFLOWS - set(raw_contracts)
        extra = set(raw_contracts) - GOVERNED_WORKFLOWS
        if missing:
            errors.append("CI contract omits workflows: " + ", ".join(sorted(missing)))
        if extra:
            errors.append("CI contract has unknown workflows: " + ", ".join(sorted(extra)))

    workflows: dict[str, dict[str, Any]] = {}
    for workflow_name in sorted(GOVERNED_WORKFLOWS):
        path = REPO_ROOT / workflow_name
        try:
            workflow = _load_workflow(path)
            actual_events = _normalized_events(workflow)
        except (OSError, UnicodeDecodeError, ValueError, yaml.YAMLError) as exc:
            errors.append(f"unable to load {workflow_name}: {exc}")
            continue
        workflows[workflow_name] = workflow

        declared = raw_contracts.get(workflow_name)
        if not isinstance(declared, dict):
            errors.append(f"workflow contract for {workflow_name} must be an object")
            continue
        expected_events = declared.get("events")
        if not isinstance(expected_events, dict):
            errors.append(f"workflow contract for {workflow_name} must define events")
            continue
        if actual_events != expected_events:
            errors.append(
                f"{workflow_name} event filters differ from contract: "
                f"expected={expected_events!r} actual={actual_events!r}"
            )

        expected_blob = declared.get("git_blob_sha")
        if expected_blob is not None:
            if (
                not isinstance(expected_blob, str)
                or re.fullmatch(r"[0-9a-f]{40}", expected_blob) is None
            ):
                errors.append(
                    f"workflow contract for {workflow_name} has invalid git_blob_sha"
                )
            elif _git_blob_sha(path) != expected_blob:
                errors.append(
                    f"{workflow_name} Git blob differs from reviewed contract identity"
                )

    release_contract = raw_contracts.get(".github/workflows/release.yml", {})
    if not isinstance(release_contract, dict) or "git_blob_sha" not in release_contract:
        errors.append("release.yml must be bound by an explicit Git blob SHA")
    return errors, workflows


def _required_context_providers() -> dict[str, list[str]]:
    providers: dict[str, list[str]] = defaultdict(list)
    for path in sorted(WORKFLOWS_DIR.glob("*.y*ml")):
        try:
            workflow = _load_workflow(path)
            events = _normalized_events(workflow)
        except (OSError, UnicodeDecodeError, ValueError, yaml.YAMLError):
            continue
        if "pull_request" not in events:
            continue
        jobs = workflow.get("jobs")
        if not isinstance(jobs, dict):
            continue
        for job_id, job in jobs.items():
            if not isinstance(job, dict):
                continue
            name = job.get("name")
            if isinstance(name, str) and name in EXPECTED_REQUIRED_CHECKS:
                providers[name].append(f"{path.name}:{job_id}")
    return providers


def _validate_ci_contract() -> tuple[list[str], list[dict[str, Any]]]:
    errors: list[str] = []
    if not CI_CONTRACT.is_file():
        return ["missing docs/development/ci-gate-contract.json"], []

    try:
        contract = _load_json_object(CI_CONTRACT)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        return [f"unable to load CI gate contract: {exc}"], []

    if contract.get("schema_version") != 3:
        errors.append("CI gate contract schema_version must equal 3")

    required_checks = contract.get("required_on_protected_main")
    if (
        not isinstance(required_checks, list)
        or len(required_checks) != len(set(required_checks))
        or set(required_checks) != EXPECTED_REQUIRED_CHECKS
    ):
        errors.append(
            "CI gate contract required-check snapshot must match protected main"
        )

    workflow_errors, workflows = _validate_workflow_contracts(contract)
    errors.extend(workflow_errors)

    checks = contract.get("checks")
    if not isinstance(checks, list) or not checks:
        return [*errors, "CI gate contract must contain a non-empty checks list"], []

    seen_job_keys: set[tuple[str, str]] = set()
    required_from_entries: set[str] = set()
    normalized_checks: list[dict[str, Any]] = []

    for index, entry in enumerate(checks):
        label = f"CI gate contract checks[{index}]"
        if not isinstance(entry, dict):
            errors.append(f"{label} must be an object")
            continue

        workflow_name = entry.get("workflow")
        job_id = entry.get("job_id")
        job_name = entry.get("job_name")
        owner = entry.get("owner")
        purpose = entry.get("purpose")
        budget = entry.get("runtime_budget")
        triage = entry.get("triage")
        required = entry.get("required_on_protected_main")
        continue_on_error = entry.get("continue_on_error")
        timeout_minutes = entry.get("timeout_minutes")

        for field_name, value in (
            ("workflow", workflow_name),
            ("job_id", job_id),
            ("job_name", job_name),
            ("owner", owner),
            ("purpose", purpose),
            ("runtime_budget", budget),
            ("triage", triage),
        ):
            if not isinstance(value, str) or not value.strip():
                errors.append(f"{label}.{field_name} must be a non-empty string")

        if not isinstance(workflow_name, str) or workflow_name not in GOVERNED_WORKFLOWS:
            continue
        if not isinstance(job_id, str) or not isinstance(job_name, str):
            continue

        job_key = (workflow_name, job_id)
        if job_key in seen_job_keys:
            errors.append(f"duplicate CI workflow/job mapping: {workflow_name}:{job_id}")
        seen_job_keys.add(job_key)

        if not isinstance(budget, str) or re.fullmatch(r"\d+-\d+ min", budget) is None:
            errors.append(f"{label}.runtime_budget must use `N-N min` format")
        if type(required) is not bool:
            errors.append(f"{label}.required_on_protected_main must be boolean")
        if type(continue_on_error) is not bool:
            errors.append(f"{label}.continue_on_error must be boolean")
        if "timeout_minutes" in entry and (
            type(timeout_minutes) is not int or timeout_minutes <= 0
        ):
            errors.append(f"{label}.timeout_minutes must be a positive integer")

        workflow = workflows.get(workflow_name)
        if workflow is None:
            continue
        jobs = workflow.get("jobs")
        if not isinstance(jobs, dict) or job_id not in jobs:
            errors.append(f"{workflow_name} does not contain job {job_id!r}")
            continue
        job = jobs[job_id]
        if not isinstance(job, dict):
            errors.append(f"{workflow_name}:{job_id} must be a job object")
            continue
        if job.get("name") != job_name:
            errors.append(
                f"{workflow_name}:{job_id} display name must be {job_name!r}"
            )

        actual_continue = job.get("continue-on-error", False)
        if type(actual_continue) is not bool or actual_continue is not continue_on_error:
            errors.append(
                f"{workflow_name}:{job_id} continue-on-error differs from contract"
            )

        if (
            "timeout_minutes" in entry
            and job.get("timeout-minutes") != timeout_minutes
        ):
            errors.append(
                f"{workflow_name}:{job_id} timeout differs from contract: "
                f"expected={timeout_minutes!r} actual={job.get('timeout-minutes')!r}"
            )

        expected_if = entry.get("job_if_equals")
        if expected_if is not None and (
            not isinstance(expected_if, str) or not expected_if.strip()
        ):
            errors.append(f"{label}.job_if_equals must be a non-empty string")
        actual_if = _normalize_expression(job.get("if"))
        normalized_expected_if = _normalize_expression(expected_if)
        if actual_if != normalized_expected_if:
            errors.append(
                f"{workflow_name}:{job_id} exact condition differs from contract: "
                f"expected={normalized_expected_if!r} actual={actual_if!r}"
            )

        if required is True:
            required_from_entries.add(job_name)
            workflow_contract = contract["workflow_contracts"][workflow_name]
            if "pull_request" not in workflow_contract["events"]:
                errors.append(
                    f"required check {job_name} lacks pull_request execution"
                )
        normalized_checks.append(entry)

    if required_from_entries != EXPECTED_REQUIRED_CHECKS:
        errors.append(
            "required check entries do not match the protected-main snapshot"
        )

    providers = _required_context_providers()
    for required_name in sorted(EXPECTED_REQUIRED_CHECKS):
        actual_providers = providers.get(required_name, [])
        if len(actual_providers) != 1:
            errors.append(
                f"required check {required_name} must have exactly one PR provider, "
                f"found {actual_providers}"
            )

    for workflow_name in sorted(GOVERNED_WORKFLOWS):
        workflow = workflows.get(workflow_name)
        if workflow is None:
            continue
        jobs = workflow.get("jobs")
        if not isinstance(jobs, dict):
            errors.append(f"{workflow_name} must contain a jobs mapping")
            continue
        actual = {(workflow_name, str(job_id)) for job_id in jobs}
        mapped = {key for key in seen_job_keys if key[0] == workflow_name}
        missing = actual - mapped
        extra = mapped - actual
        if missing:
            errors.append(
                f"CI contract omits jobs from {workflow_name}: "
                + ", ".join(sorted(job_id for _, job_id in missing))
            )
        if extra:
            errors.append(
                f"CI contract names unknown jobs in {workflow_name}: "
                + ", ".join(sorted(job_id for _, job_id in extra))
            )
    return errors, normalized_checks


def _validate_documentation(checks: list[dict[str, Any]]) -> list[str]:
    errors: list[str] = []
    documentation_checks = {
        SCRIPT_README: "docs/development/CONTRIBUTOR_COMMANDS.md",
        DEVELOPMENT_README: "CONTRIBUTOR_COMMANDS.md",
        CONTRIBUTING: "CONTRIBUTOR_COMMANDS.md",
    }
    for path, expected_link in documentation_checks.items():
        if not path.is_file():
            errors.append(f"missing documentation index: {path.relative_to(REPO_ROOT)}")
            continue
        if expected_link not in path.read_text(encoding="utf-8"):
            errors.append(
                f"{path.relative_to(REPO_ROOT)} does not link the command contract"
            )

    if not CONTRACT_DOC.is_file():
        return [*errors, "missing contributor command contract document"]

    text = CONTRACT_DOC.read_text(encoding="utf-8")
    for command in (*EXPECTED_DELEGATES, "help"):
        if f"`{command}" not in text:
            errors.append(f"command contract does not document {command}")
    for required_section in (
        "## Stable Commands",
        "## Advanced Surface",
        "## CI Gate Map",
        "## Change Policy",
        "## Validation",
    ):
        if required_section not in text:
            errors.append(f"command contract is missing {required_section}")
    for required_term in (
        "ci-gate-contract.json",
        "| Check | Workflow | Execution lane | Budget | Owner | Purpose | First triage action |",
        "Backend SQLite Regression",
        "Production Profile Smoke",
        "Docker Onboarding Smoke (Scheduled)",
        "Create GitHub Release",
        "Git blob SHA",
        "stops local development processes",
        "intentionally keeps `backend/venv`",
        "not SLAs",
        "lint lint-types",
    ):
        if required_term not in text:
            errors.append(f"command contract is missing term: {required_term}")

    for entry in checks:
        workflow_name = Path(str(entry["workflow"])).name
        job_name = str(entry["job_name"])
        row_prefix = f"| `{job_name}` | `{workflow_name}` |"
        if row_prefix not in text:
            errors.append(
                f"human CI map is missing workflow/job row: {workflow_name}:{job_name}"
            )
    return errors


def validate() -> list[str]:
    ci_errors, checks = _validate_ci_contract()
    return [
        *_validate_facade(),
        *ci_errors,
        *_validate_documentation(checks),
    ]


def main() -> int:
    errors = validate()
    if errors:
        for error in errors:
            print(f"contributor-command error: {error}", file=sys.stderr)
        return 1
    print("Contributor command and exact CI contract: valid")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
