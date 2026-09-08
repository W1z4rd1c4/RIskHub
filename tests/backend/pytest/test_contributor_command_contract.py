from __future__ import annotations

import hashlib
import importlib.util
import json
import subprocess
import sys
from pathlib import Path
from types import ModuleType

REPO_ROOT = Path(__file__).resolve().parents[3]
FACADE = REPO_ROOT / "scripts/riskhub.sh"
CI_CONTRACT = REPO_ROOT / "docs/development/ci-gate-contract.json"
CONTRACT_DOC = REPO_ROOT / "docs/development/CONTRIBUTOR_COMMANDS.md"
VALIDATOR = REPO_ROOT / "scripts/tools/validate_contributor_command_contract.py"
STARTUP_SMOKE = REPO_ROOT / ".github/workflows/startup-smoke.yml"
STARTUP_SMOKE_PR = REPO_ROOT / ".github/workflows/startup-smoke-pr.yml"
RELEASE_WORKFLOW = REPO_ROOT / ".github/workflows/release.yml"
PYTHON_DEV_LOCK_REFRESH = (
    REPO_ROOT / ".github/workflows/python-dev-lock-refresh.yml"
)
FRONTEND_CONTAINER_GATE_CONTRACT = (
    REPO_ROOT / ".github/workflows/frontend-container-gate-contract.yml"
)


def _ci_contract() -> dict:
    return json.loads(CI_CONTRACT.read_text(encoding="utf-8"))


def _validator_module() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "riskhub_contributor_contract_validator",
        VALIDATOR,
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _git_blob_sha(path: Path) -> str:
    data = path.read_bytes()
    return hashlib.sha1(f"blob {len(data)}\0".encode() + data).hexdigest()


def test_contributor_command_contract():
    subprocess.run(
        [sys.executable, str(VALIDATOR)],
        cwd=REPO_ROOT,
        check=True,
    )


def test_contributor_command_help_lists_stable_surface():
    result = subprocess.run(
        [str(FACADE), "help"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=True,
    )

    for command in (
        "setup",
        "dev",
        "lint",
        "test",
        "e2e",
        "release-check",
        "clean",
    ):
        assert command in result.stdout

    assert "Repair and start local development services" in result.stdout
    assert "Run the default backend regression contract" in result.stdout
    assert "Stop local dev/Compose" in result.stdout
    assert "keep backend/venv" in result.stdout
    assert "remove local containers, volumes, dependencies" not in result.stdout


def test_human_ci_map_covers_every_machine_mapped_workflow_job():
    payload = _ci_contract()
    documentation = CONTRACT_DOC.read_text(encoding="utf-8")

    job_keys = [
        (check["workflow"], check["job_id"])
        for check in payload["checks"]
    ]
    assert len(job_keys) == len(set(job_keys))
    for check in payload["checks"]:
        workflow_name = Path(check["workflow"]).name
        assert f"| `{check['job_name']}` | `{workflow_name}` |" in documentation


def test_ci_contract_includes_release_publication_workflow_and_blob_identity():
    payload = _ci_contract()

    assert payload["schema_version"] == 3
    release_contract = payload["workflow_contracts"][
        ".github/workflows/release.yml"
    ]
    assert release_contract["git_blob_sha"] == _git_blob_sha(RELEASE_WORKFLOW)

    release_jobs = {
        check["job_id"]
        for check in payload["checks"]
        if check["workflow"] == ".github/workflows/release.yml"
    }
    assert release_jobs == {
        "workflow-pin-validation",
        "prepare",
        "release-parity-gate",
        "docker-images",
        "linux-bundle",
        "verify-linux-bundle",
        "create-release",
    }
    for check in payload["checks"]:
        assert check["owner"].strip()
        assert check["purpose"].strip()
        assert check["runtime_budget"].strip()
        assert check["triage"].strip()


def test_docker_onboarding_required_context_has_one_pr_provider():
    module = _validator_module()
    providers = module._required_context_providers()

    assert providers["Docker Onboarding Smoke"] == [
        "startup-smoke-pr.yml:docker-onboarding-smoke"
    ]
    assert "pull_request:" not in STARTUP_SMOKE.read_text(encoding="utf-8")
    assert "pull_request:" in STARTUP_SMOKE_PR.read_text(encoding="utf-8")


def test_ci_contract_records_exact_branch_path_tag_and_schedule_filters():
    events = _ci_contract()["workflow_contracts"]

    assert events[".github/workflows/startup-smoke-pr.yml"]["events"] == {
        "pull_request": {"branches": ["main", "develop", "feat/identity-group-*"]},
    }
    assert events[".github/workflows/startup-smoke.yml"]["events"] == {
        "push": {"branches": ["main", "develop"]},
        "schedule": {"crons": ["45 2 * * *"]},
        "workflow_dispatch": {"inputs": []},
    }

    maintenance_pr = events[
        ".github/workflows/maintenance-governance.yml"
    ]["events"]["pull_request"]
    assert maintenance_pr["branches"] == ["main", "develop", "feat/identity-group-*"]
    assert maintenance_pr["paths"] == [
        "AGENTS.md",
        ".planning/**",
        "docs/**",
        "scripts/check_docs_contract.py",
        "scripts/quality/**",
        "scripts/tools/**",
        "frontend/scripts/**",
        "backend/mypy.ini",
        "backend/ruff.toml",
        ".github/workflows/**",
    ]

    assert events[".github/workflows/release.yml"]["events"] == {
        "push": {"tags": ["v*"]},
        "workflow_dispatch": {"inputs": ["version"]},
    }


def test_ci_contract_governs_python_dev_lock_refresh_workflow():
    payload = _ci_contract()
    workflow_name = ".github/workflows/python-dev-lock-refresh.yml"

    assert payload["workflow_contracts"][workflow_name]["events"] == {
        "schedule": {"crons": ["17 6 1 * *"]},
        "workflow_dispatch": {"inputs": []},
    }

    checks = [
        check for check in payload["checks"] if check["workflow"] == workflow_name
    ]
    assert len(checks) == 1
    assert checks[0]["job_id"] == "refresh"
    assert checks[0]["job_if_equals"] == "github.ref == 'refs/heads/main'"
    assert checks[0]["timeout_minutes"] == 20
    assert checks[0]["required_on_protected_main"] is False
    assert checks[0]["continue_on_error"] is False
    assert "only when resolver output changes" in checks[0]["purpose"]
    assert "RISKHUB_AUTOMATION_PR_TOKEN" in checks[0]["triage"]

    workflow = PYTHON_DEV_LOCK_REFRESH.read_text(encoding="utf-8")
    assert "RISKHUB_AUTOMATION_PR_TOKEN" in workflow
    assert "Open lock refresh pull request" in workflow
    assert "changed=false" in workflow


def test_ci_contract_governs_frontend_container_gate_contract_workflow():
    module = _validator_module()
    payload = _ci_contract()
    workflow_name = ".github/workflows/frontend-container-gate-contract.yml"
    relevant_paths = [
        ".github/workflows/frontend-container-gate-contract.yml",
        ".github/workflows/security.yml",
        "scripts/security/frontend_trivy_status.py",
        "scripts/security/validate_frontend_container_gate.py",
        "tests/backend/pytest/test_frontend_container_security_contract.py",
    ]

    assert workflow_name in module.GOVERNED_WORKFLOWS
    assert payload["workflow_contracts"][workflow_name]["events"] == {
        "pull_request": {
            "branches": ["main", "develop", "feat/identity-group-*"],
            "paths": relevant_paths,
        },
        "push": {
            "branches": ["main", "develop"],
            "paths": relevant_paths,
        },
        "workflow_dispatch": {"inputs": []},
    }

    checks = [
        check for check in payload["checks"] if check["workflow"] == workflow_name
    ]
    assert len(checks) == 1
    check = checks[0]
    assert check["job_id"] == "injected-finding-contract"
    assert check["job_name"] == "Frontend Container Injected Finding Contract"
    assert check["owner"] == "Security/Supply Chain"
    assert check["runtime_budget"] == "1-5 min"
    assert check["required_on_protected_main"] is False
    assert check["continue_on_error"] is False
    assert "injected qualifying CRITICAL" in check["purpose"]
    assert "frontend-container-injected-finding-evidence" in check["triage"]

    workflow = FRONTEND_CONTAINER_GATE_CONTRACT.read_text(encoding="utf-8")
    assert "frontend-container-injected-finding-evidence" in workflow


def test_job_condition_normalization_is_exact_not_substring_based():
    module = _validator_module()
    expected = "github.event_name == 'pull_request'"

    assert module._normalize_expression(f"${{{{ {expected} }}}}") == expected
    assert module._normalize_expression(f"{expected} && false") != expected


def test_contributor_command_rejects_unknown_command():
    result = subprocess.run(
        [str(FACADE), "unknown-command"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 2
    assert "Unknown RiskHub command" in result.stderr


def test_identity_stack_gates_preserve_push_and_blocking_semantics():
    payload = _ci_contract()
    for basename in ("lint.yml", "backend-postgres.yml", "e2e.yml", "security.yml"):
        events = payload["workflow_contracts"][f".github/workflows/{basename}"]["events"]
        assert events["pull_request"]["branches"] == ["main", "develop", "feat/identity-group-*"]
        assert events["push"]["branches"] == ["main", "develop"]
    identity_checks = [
        check for check in payload["checks"]
        if Path(check["workflow"]).name.startswith("identity-")
    ]
    assert len(identity_checks) == 2
    for check in identity_checks:
        assert check["continue_on_error"] is False
        assert check["required_on_protected_main"] is False
        assert check["timeout_minutes"] > 0
