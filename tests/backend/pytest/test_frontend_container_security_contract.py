from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path
from types import ModuleType

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[3]
VALIDATOR = REPO_ROOT / "scripts/security/validate_frontend_container_gate.py"
STATUS_HELPER = REPO_ROOT / "scripts/security/frontend_trivy_status.py"
SECURITY_WORKFLOW = REPO_ROOT / ".github/workflows/security.yml"
CONTRACT_WORKFLOW = REPO_ROOT / ".github/workflows/frontend-container-gate-contract.yml"
HOSTED_TRIVY_V070_SARIF_SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/"
    "sarif-2.1/schema/sarif-schema-2.1.0.json"
)
PINNED_CANONICAL_SARIF_SCHEMA = (
    "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/"
    "schemas/sarif-schema-2.1.0.json"
)
SARIF_SCHEMA = PINNED_CANONICAL_SARIF_SCHEMA


def _run_status(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(STATUS_HELPER), *args],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )


def _validator_module() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "riskhub_frontend_container_validator",
        VALIDATOR,
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _validate_workflow_text(tmp_path: Path, workflow: str) -> list[str]:
    module = _validator_module()
    mutated = tmp_path / "security.yml"
    mutated.write_text(workflow, encoding="utf-8")
    module.WORKFLOW_PATH = mutated
    return module.validate()


def _validate_contract_workflow_text(tmp_path: Path, workflow: str) -> list[str]:
    module = _validator_module()
    mutated = tmp_path / "frontend-container-gate-contract.yml"
    mutated.write_text(workflow, encoding="utf-8")
    module.CONTRACT_WORKFLOW_PATH = mutated
    return module.validate()


def _write_sarif(
    path: Path,
    *,
    findings: int = 0,
    severity: str = "CRITICAL",
    schema_uri: str = SARIF_SCHEMA,
    include_messages: bool = True,
    rules_override: list[object] | None = None,
) -> None:
    rules: list[object] = []
    results: list[dict[str, object]] = []
    for index in range(findings):
        rule_id = f"CVE-TEST-{index}"
        rules.append(
            {
                "id": rule_id,
                "name": "InjectedContainerVulnerability",
                "defaultConfiguration": {"level": "error"},
                "properties": {
                    "security-severity": "9.8",
                    "tags": ["vulnerability", "security", severity],
                },
            }
        )
        result: dict[str, object] = {
            "ruleId": rule_id,
            "ruleIndex": index,
            "level": "error",
        }
        if include_messages:
            result["message"] = {"text": f"Injected test finding {index}"}
        results.append(result)

    path.write_text(
        json.dumps(
            {
                "$schema": schema_uri,
                "version": "2.1.0",
                "runs": [
                    {
                        "tool": {
                            "driver": {
                                "name": "Trivy",
                                "fullName": "Trivy Vulnerability Scanner",
                                "informationUri": "https://github.com/aquasecurity/trivy",
                                "rules": rules if rules_override is None else rules_override,
                            }
                        },
                        "results": results,
                    }
                ],
            }
        )
        + "\n",
        encoding="utf-8",
    )


def _record_status(*, sarif: Path, status: Path, outcome: str = "success") -> dict:
    recorded = _run_status(
        "record",
        "--outcome",
        outcome,
        "--sarif",
        str(sarif),
        "--output",
        str(status),
    )
    assert recorded.returncode == 0, recorded.stderr
    return json.loads(status.read_text(encoding="utf-8"))


def test_frontend_container_vulnerability_gate_contract() -> None:
    subprocess.run(
        [sys.executable, str(VALIDATOR)],
        cwd=REPO_ROOT,
        check=True,
    )


def test_frontend_container_gate_accepts_clean_retained_status(tmp_path: Path) -> None:
    sarif = tmp_path / "trivy-frontend.sarif"
    status = tmp_path / "frontend-status.json"
    _write_sarif(sarif)

    payload = _record_status(sarif=sarif, status=status)
    assert payload["status"] == "clean"
    assert payload["scanner"] == "trivy"
    assert payload["image"] == "riskhub-frontend:scan"
    assert len(payload["sarif_sha256"]) == 64

    enforced = _run_status("enforce", "--status-file", str(status))
    assert enforced.returncode == 0, enforced.stderr
    assert "status=clean" in enforced.stdout


def test_frontend_container_gate_accepts_pinned_canonical_sarif_schema(
    tmp_path: Path,
) -> None:
    sarif = tmp_path / "trivy-frontend.sarif"
    status = tmp_path / "frontend-status.json"
    _write_sarif(sarif, schema_uri=PINNED_CANONICAL_SARIF_SCHEMA)

    payload = _record_status(sarif=sarif, status=status)
    assert payload["status"] == "clean"
    assert payload["sarif_valid"] is True


def test_frontend_container_gate_accepts_hosted_trivy_v070_sarif_schema(
    tmp_path: Path,
) -> None:
    sarif = tmp_path / "trivy-frontend.sarif"
    status = tmp_path / "frontend-status.json"
    _write_sarif(sarif, schema_uri=HOSTED_TRIVY_V070_SARIF_SCHEMA)

    payload = _record_status(sarif=sarif, status=status)
    assert payload["status"] == "clean"
    assert payload["sarif_valid"] is True


def test_frontend_container_gate_retains_missing_sarif_failure(tmp_path: Path) -> None:
    status = tmp_path / "frontend-status.json"
    missing = tmp_path / "trivy-frontend.sarif"

    payload = _record_status(sarif=missing, status=status, outcome="failure")
    assert payload["status"] == "scan_failed"
    assert payload["reason"] == "sarif_missing"
    assert payload["sarif_present"] is False
    assert payload["sarif_sha256"] is None

    enforced = _run_status("enforce", "--status-file", str(status))
    assert enforced.returncode != 0
    assert "status=scan_failed" in enforced.stdout


def test_frontend_container_gate_rejects_qualifying_findings(tmp_path: Path) -> None:
    sarif = tmp_path / "trivy-frontend.sarif"
    status = tmp_path / "frontend-status.json"
    _write_sarif(sarif, findings=2, severity="CRITICAL")

    payload = _record_status(sarif=sarif, status=status)
    assert payload["status"] == "findings"
    assert payload["finding_count"] == 2

    enforced = _run_status("enforce", "--status-file", str(status))
    assert enforced.returncode != 0
    assert "status=findings" in enforced.stdout


def test_frontend_container_gate_rejects_nonqualifying_result(tmp_path: Path) -> None:
    sarif = tmp_path / "trivy-frontend.sarif"
    status = tmp_path / "frontend-status.json"
    _write_sarif(sarif, findings=1, severity="MEDIUM")

    payload = _record_status(sarif=sarif, status=status)
    assert payload["status"] == "evidence_invalid"
    assert payload["reason"] == "sarif_nonqualifying_result"


def test_frontend_container_gate_rejects_malformed_rule_entries(tmp_path: Path) -> None:
    sarif = tmp_path / "trivy-frontend.sarif"
    status = tmp_path / "frontend-status.json"
    _write_sarif(sarif, rules_override=[None])

    payload = _record_status(sarif=sarif, status=status)
    assert payload["status"] == "evidence_invalid"
    assert payload["reason"] == "sarif_invalid_rules"


def test_frontend_container_gate_rejects_invalid_sarif_evidence(tmp_path: Path) -> None:
    sarif = tmp_path / "trivy-frontend.sarif"
    status = tmp_path / "frontend-status.json"
    sarif.write_text("not-json", encoding="utf-8")

    payload = _record_status(sarif=sarif, status=status)
    assert payload["status"] == "evidence_invalid"
    assert payload["reason"] == "sarif_invalid_json"

    enforced = _run_status("enforce", "--status-file", str(status))
    assert enforced.returncode != 0


def test_frontend_container_gate_rejects_sarif_without_trivy_tool(tmp_path: Path) -> None:
    sarif = tmp_path / "trivy-frontend.sarif"
    status = tmp_path / "frontend-status.json"
    sarif.write_text(
        json.dumps(
            {
                "$schema": SARIF_SCHEMA,
                "version": "2.1.0",
                "runs": [{}],
            }
        ),
        encoding="utf-8",
    )

    payload = _record_status(sarif=sarif, status=status)
    assert payload["status"] == "evidence_invalid"
    assert payload["reason"] == "sarif_invalid_tool"

    enforced = _run_status("enforce", "--status-file", str(status))
    assert enforced.returncode != 0


def test_frontend_container_gate_rejects_attacker_controlled_schema_uri(
    tmp_path: Path,
) -> None:
    sarif = tmp_path / "trivy-frontend.sarif"
    status = tmp_path / "frontend-status.json"
    _write_sarif(
        sarif,
        schema_uri="https://attacker.invalid/sarif-2.1.0-schema.json",
    )

    payload = _record_status(sarif=sarif, status=status)
    assert payload["status"] == "evidence_invalid"
    assert payload["reason"] == "sarif_invalid_schema"

    enforced = _run_status("enforce", "--status-file", str(status))
    assert enforced.returncode != 0


def test_frontend_container_gate_rejects_result_without_message(
    tmp_path: Path,
) -> None:
    sarif = tmp_path / "trivy-frontend.sarif"
    status = tmp_path / "frontend-status.json"
    _write_sarif(sarif, findings=1, include_messages=False)

    payload = _record_status(sarif=sarif, status=status)
    assert payload["status"] == "evidence_invalid"
    assert payload["reason"] == "sarif_invalid_result_message"

    enforced = _run_status("enforce", "--status-file", str(status))
    assert enforced.returncode != 0


def test_frontend_container_gate_rejects_truncated_clean_status(tmp_path: Path) -> None:
    status = tmp_path / "frontend-status.json"
    status.write_text(
        json.dumps({"schema_version": 1, "status": "clean"}),
        encoding="utf-8",
    )

    enforced = _run_status("enforce", "--status-file", str(status))
    assert enforced.returncode != 0
    assert "missing required fields" in enforced.stderr


def test_frontend_container_gate_rejects_unknown_status_fields(tmp_path: Path) -> None:
    sarif = tmp_path / "trivy-frontend.sarif"
    status = tmp_path / "frontend-status.json"
    _write_sarif(sarif)
    payload = _record_status(sarif=sarif, status=status)
    payload["attacker_controlled"] = True
    status.write_text(json.dumps(payload), encoding="utf-8")

    enforced = _run_status("enforce", "--status-file", str(status))
    assert enforced.returncode != 0
    assert "unknown fields" in enforced.stderr


def test_frontend_container_gate_rejects_tampered_clean_sarif(tmp_path: Path) -> None:
    sarif = tmp_path / "trivy-frontend.sarif"
    status = tmp_path / "frontend-status.json"
    _write_sarif(sarif)
    payload = _record_status(sarif=sarif, status=status)
    assert payload["status"] == "clean"

    _write_sarif(sarif, findings=1)
    enforced = _run_status("enforce", "--status-file", str(status))
    assert enforced.returncode != 0
    assert (
        "now contains findings" in enforced.stderr
        or "digest does not match" in enforced.stderr
    )


def test_contract_validator_rejects_expression_based_advisory_mode() -> None:
    module = _validator_module()
    errors: list[str] = []
    module._reject_continue_on_error(
        errors,
        "test gate",
        {"continue-on-error": "${{ true }}"},
    )
    assert any("continue-on-error" in error for error in errors)


def test_contract_validator_rejects_ignore_unfixed(tmp_path: Path) -> None:
    workflow = SECURITY_WORKFLOW.read_text(encoding="utf-8")
    workflow = workflow.replace(
        "          exit-code: '1'\n",
        "          exit-code: '1'\n          ignore-unfixed: true\n",
        1,
    )
    errors = _validate_workflow_text(tmp_path, workflow)
    assert any("ignore-unfixed" in error for error in errors)


def test_contract_validator_requires_vulnerability_only_scanner(
    tmp_path: Path,
) -> None:
    workflow = SECURITY_WORKFLOW.read_text(encoding="utf-8")
    workflow = workflow.replace(
        "          scanners: 'vuln'\n",
        "          scanners: 'secret'\n",
        1,
    )
    errors = _validate_workflow_text(tmp_path, workflow)
    assert any("scanners" in error and "vuln" in error for error in errors)


@pytest.mark.parametrize(
    ("option", "value"),
    [
        ("secret", "${{ github.token }}"),
        ("trivyignores", ".trivyignore"),
        ("skip-files", "usr/lib/vulnerable.so"),
        ("ignore-policy", "policy.rego"),
        ("trivy-config", "trivy.yaml"),
        ("skip-dirs", "usr/lib"),
        ("unknown-scan-option", "enabled"),
    ],
)
def test_contract_validator_rejects_extra_frontend_scan_inputs(
    tmp_path: Path,
    option: str,
    value: str,
) -> None:
    workflow = SECURITY_WORKFLOW.read_text(encoding="utf-8")
    anchor = "          scanners: 'vuln'\n"
    if anchor not in workflow:
        anchor = "          exit-code: '1'\n"
    workflow = workflow.replace(anchor, f"{anchor}          {option}: {value}\n", 1)
    errors = _validate_workflow_text(tmp_path, workflow)
    assert any(option in error for error in errors)


@pytest.mark.parametrize(
    ("anchor", "injected"),
    [
        (
            "permissions:\n  contents: read\n  security-events: write\n",
            "permissions:\n  contents: read\n  security-events: write\n\n"
            "env:\n  TRIVY_SKIP_FILES: usr/lib/vulnerable.so\n",
        ),
        (
            "  container-security:\n"
            "    name: Container Scan (Trivy + SBOM Correlation)\n"
            "    runs-on: ubuntu-latest\n",
            "  container-security:\n"
            "    name: Container Scan (Trivy + SBOM Correlation)\n"
            "    runs-on: ubuntu-latest\n"
            "    env:\n      TRIVY_IGNORE_POLICY: policy.rego\n",
        ),
        (
            "        continue-on-error: true\n        uses: aquasecurity/trivy-action@",
            "        continue-on-error: true\n"
            "        env:\n          TRIVY_SCANNERS: secret\n"
            "        uses: aquasecurity/trivy-action@",
        ),
    ],
)
def test_contract_validator_rejects_trivy_environment_overrides(
    tmp_path: Path,
    anchor: str,
    injected: str,
) -> None:
    workflow = SECURITY_WORKFLOW.read_text(encoding="utf-8")
    workflow = workflow.replace(anchor, injected, 1)
    errors = _validate_workflow_text(tmp_path, workflow)
    assert any("TRIVY_" in error for error in errors)


def test_contract_validator_requires_pull_request_trigger(tmp_path: Path) -> None:
    workflow = SECURITY_WORKFLOW.read_text(encoding="utf-8").replace(
        "  pull_request:\n    branches: [main, develop, \"feat/identity-group-*\"]\n",
        "",
        1,
    )
    errors = _validate_workflow_text(tmp_path, workflow)
    assert any("pull_request" in error for error in errors)


def test_contract_validator_requires_push_to_main(tmp_path: Path) -> None:
    workflow = SECURITY_WORKFLOW.read_text(encoding="utf-8").replace(
        "  push:\n    branches: [main, develop]\n",
        "  push:\n    branches: [develop]\n",
        1,
    )
    errors = _validate_workflow_text(tmp_path, workflow)
    assert any("push" in error and "main" in error for error in errors)


def test_contract_validator_requires_scheduled_runs(tmp_path: Path) -> None:
    workflow = SECURITY_WORKFLOW.read_text(encoding="utf-8").replace(
        "  schedule:\n"
        "    # Run nightly at 02:00 UTC for resilience smoke checks\n"
        "    - cron: '0 2 * * *'\n"
        "    # Run weekly on Sunday at 00:00 UTC\n"
        "    - cron: '0 0 * * 0'\n",
        "",
        1,
    )
    errors = _validate_workflow_text(tmp_path, workflow)
    assert any("schedule" in error for error in errors)


def test_contract_validator_rejects_conditional_container_job(tmp_path: Path) -> None:
    workflow = SECURITY_WORKFLOW.read_text(encoding="utf-8").replace(
        "  container-security:\n    name: Container Scan (Trivy + SBOM Correlation)\n",
        "  container-security:\n    name: Container Scan (Trivy + SBOM Correlation)\n    if: false\n",
        1,
    )
    errors = _validate_workflow_text(tmp_path, workflow)
    assert any(
        "container-security job" in error and "conditional" in error
        for error in errors
    )


@pytest.mark.parametrize("filename", [".trivyignore", "trivy.yaml"])
def test_contract_validator_rejects_default_trivy_files(
    tmp_path: Path,
    filename: str,
) -> None:
    module = _validator_module()
    module.REPO_ROOT = tmp_path
    (tmp_path / filename).write_text("ignored-by-default\n", encoding="utf-8")
    errors = module.validate()
    assert any(filename in error for error in errors)


@pytest.mark.parametrize(
    "replacement",
    [
        "echo python3 scripts/security/frontend_trivy_status.py enforce "
        "--status-file trivy-frontend-status.json",
        "# python3 scripts/security/frontend_trivy_status.py enforce "
        "--status-file trivy-frontend-status.json",
        "true # python3 scripts/security/frontend_trivy_status.py enforce "
        "--status-file trivy-frontend-status.json",
    ],
)
def test_contract_validator_rejects_noop_enforcement_commands(
    tmp_path: Path,
    replacement: str,
) -> None:
    workflow = SECURITY_WORKFLOW.read_text(encoding="utf-8")
    original = (
        "        run: >-\n"
        "          python3 scripts/security/frontend_trivy_status.py enforce\n"
        "          --status-file trivy-frontend-status.json\n"
    )
    workflow = workflow.replace(original, f"        run: {json.dumps(replacement)}\n", 1)
    errors = _validate_workflow_text(tmp_path, workflow)
    assert any("enforcement command" in error for error in errors)


def test_contract_validator_rejects_noop_status_recorder(tmp_path: Path) -> None:
    workflow = SECURITY_WORKFLOW.read_text(encoding="utf-8").replace(
        "          python3 scripts/security/frontend_trivy_status.py record \\\n",
        "          echo python3 scripts/security/frontend_trivy_status.py record \\\n",
        1,
    )
    errors = _validate_workflow_text(tmp_path, workflow)
    assert any("recorder command" in error for error in errors)


@pytest.mark.parametrize(
    ("anchor", "injected"),
    [
        (
            "  pull_request:\n    branches: [main, develop, \"feat/identity-group-*\"]\n",
            "  pull_request:\n    branches: [main, develop, \"feat/identity-group-*\"]\n"
            "    paths: ['frontend/**']\n",
        ),
        (
            "  pull_request:\n    branches: [main, develop, \"feat/identity-group-*\"]\n",
            "  pull_request:\n    branches: [main, develop, \"feat/identity-group-*\"]\n"
            "    paths-ignore: ['docs/**']\n",
        ),
        (
            "  pull_request:\n    branches: [main, develop, \"feat/identity-group-*\"]\n",
            "  pull_request:\n    branches: [main, develop, \"feat/identity-group-*\"]\n"
            "    types: [opened]\n",
        ),
        (
            "  pull_request:\n    branches: [main, develop, \"feat/identity-group-*\"]\n",
            "  pull_request:\n    branches: [main, develop, '!main']\n",
        ),
        (
            "  pull_request:\n    branches: [main, develop, \"feat/identity-group-*\"]\n",
            "  pull_request:\n    branches: [main, develop, \"feat/identity-group-*\"]\n"
            "    branches-ignore: ['release/**']\n",
        ),
        (
            "  push:\n    branches: [main, develop]\n",
            "  push:\n    branches: [main, develop]\n    tags: ['v*']\n",
        ),
    ],
)
def test_contract_validator_rejects_narrowed_production_triggers(
    tmp_path: Path,
    anchor: str,
    injected: str,
) -> None:
    workflow = SECURITY_WORKFLOW.read_text(encoding="utf-8").replace(
        anchor,
        injected,
        1,
    )
    errors = _validate_workflow_text(tmp_path, workflow)
    assert any("trigger" in error for error in errors)


def test_contract_validator_rejects_container_job_dependency(tmp_path: Path) -> None:
    workflow = SECURITY_WORKFLOW.read_text(encoding="utf-8").replace(
        "  container-security:\n"
        "    name: Container Scan (Trivy + SBOM Correlation)\n",
        "  container-security:\n"
        "    name: Container Scan (Trivy + SBOM Correlation)\n"
        "    needs: disabled-prerequisite\n",
        1,
    )
    errors = _validate_workflow_text(tmp_path, workflow)
    assert any("container-security job" in error and "needs" in error for error in errors)


@pytest.mark.parametrize(
    "dependency",
    ["    if: false\n", "    needs: disabled-prerequisite\n"],
)
def test_contract_validator_rejects_skippable_injected_proof_job(
    tmp_path: Path,
    dependency: str,
) -> None:
    workflow = CONTRACT_WORKFLOW.read_text(encoding="utf-8").replace(
        "  injected-finding-contract:\n"
        "    name: Frontend Container Injected Finding Contract\n",
        "  injected-finding-contract:\n"
        "    name: Frontend Container Injected Finding Contract\n"
        f"{dependency}",
        1,
    )
    errors = _validate_contract_workflow_text(tmp_path, workflow)
    assert any("injected-finding contract job" in error for error in errors)


@pytest.mark.parametrize(
    ("contract", "anchor"),
    [
        (False, "name: Security Scanning\n"),
        (
            False,
            "  container-security:\n"
            "    name: Container Scan (Trivy + SBOM Correlation)\n"
            "    runs-on: ubuntu-latest\n",
        ),
        (True, "name: Frontend Container Gate Contract\n"),
        (
            True,
            "  injected-finding-contract:\n"
            "    name: Frontend Container Injected Finding Contract\n"
            "    runs-on: ubuntu-latest\n",
        ),
    ],
)
def test_contract_validator_rejects_run_defaults(
    tmp_path: Path,
    contract: bool,
    anchor: str,
) -> None:
    source = CONTRACT_WORKFLOW if contract else SECURITY_WORKFLOW
    workflow = source.read_text(encoding="utf-8").replace(
        anchor,
        f"{anchor}defaults:\n  run:\n    shell: echo {{0}}\n"
        if not anchor.startswith("  ")
        else f"{anchor}    defaults:\n      run:\n        shell: echo {{0}}\n",
        1,
    )
    errors = (
        _validate_contract_workflow_text(tmp_path, workflow)
        if contract
        else _validate_workflow_text(tmp_path, workflow)
    )
    assert any("defaults" in error for error in errors)


@pytest.mark.parametrize(
    ("step_name", "metadata", "expected"),
    [
        ("Record Frontend Trivy Scan Status", "        shell: echo {0}\n", "keys"),
        ("Record Frontend Trivy Scan Status", "        working-directory: /tmp\n", "keys"),
        ("Record Frontend Trivy Scan Status", "", "always"),
        ("Enforce Frontend Trivy HIGH/CRITICAL Gate", "        shell: echo {0}\n", "keys"),
        ("Enforce Frontend Trivy HIGH/CRITICAL Gate", "        working-directory: /tmp\n", "keys"),
        ("Enforce Frontend Trivy HIGH/CRITICAL Gate", "", "always"),
    ],
)
def test_contract_validator_closes_production_critical_step_metadata(
    tmp_path: Path,
    step_name: str,
    metadata: str,
    expected: str,
) -> None:
    workflow = SECURITY_WORKFLOW.read_text(encoding="utf-8")
    anchor = f"      - name: {step_name}\n"
    if metadata:
        workflow = workflow.replace(anchor, f"{anchor}{metadata}", 1)
    else:
        workflow = workflow.replace(
            f"{anchor}        if: always()\n",
            f"{anchor}        if: false\n",
            1,
        )
    errors = _validate_workflow_text(tmp_path, workflow)
    assert any(expected in error for error in errors)


@pytest.mark.parametrize(
    ("step_name", "metadata"),
    [
        ("Generate injected Trivy SARIF finding", "        shell: echo {0}\n"),
        ("Record injected frontend finding", "        working-directory: /tmp\n"),
        ("Prove injected finding is blocked", "        if: false\n"),
        ("Validate production workflow contract", "        shell: echo {0}\n"),
    ],
)
def test_contract_validator_closes_injected_critical_step_metadata(
    tmp_path: Path,
    step_name: str,
    metadata: str,
) -> None:
    workflow = CONTRACT_WORKFLOW.read_text(encoding="utf-8")
    anchor = f"      - name: {step_name}\n"
    workflow = workflow.replace(anchor, f"{anchor}{metadata}", 1)
    errors = _validate_contract_workflow_text(tmp_path, workflow)
    assert any("keys" in error or "exact" in error for error in errors)


@pytest.mark.parametrize(
    "injection",
    [
        "echo 'TRIVY_IGNORE_UNFIXED=true' >> \"$GITHUB_ENV\"",
        "echo 'TRIVY_IGNOREFILE=.trivyignore' >> \"${GITHUB_ENV}\"",
        "export TRIVY_CONFIG=trivy.yaml",
    ],
)
def test_contract_validator_rejects_pre_scan_trivy_injection(
    tmp_path: Path,
    injection: str,
) -> None:
    workflow = SECURITY_WORKFLOW.read_text(encoding="utf-8").replace(
        "        run: docker build -t riskhub-frontend:scan -f frontend/Dockerfile frontend/\n",
        "        run: |\n"
        "          docker build -t riskhub-frontend:scan -f frontend/Dockerfile frontend/\n"
        f"          {injection}\n",
        1,
    )
    errors = _validate_workflow_text(tmp_path, workflow)
    assert any("pre-scan" in error or "TRIVY_" in error for error in errors)


@pytest.mark.parametrize(
    ("needle", "replacement"),
    [
        (
            "          python3 scripts/security/frontend_trivy_status.py record \\\n",
            "          echo python3 scripts/security/frontend_trivy_status.py record \\\n",
        ),
        (
            "          if python3 scripts/security/frontend_trivy_status.py enforce \\\n",
            "          if echo python3 scripts/security/frontend_trivy_status.py enforce \\\n",
        ),
        (
            "          if python3 scripts/security/frontend_trivy_status.py enforce \\\n",
            "          # if python3 scripts/security/frontend_trivy_status.py enforce \\\n",
        ),
        (
            "      - name: Prove injected finding is blocked\n        run: |\n",
            "      - name: Prove injected finding is blocked\n"
            "        run: |\n          exit 0\n",
        ),
    ],
)
def test_contract_validator_locks_injected_proof_scripts(
    tmp_path: Path,
    needle: str,
    replacement: str,
) -> None:
    workflow = CONTRACT_WORKFLOW.read_text(encoding="utf-8").replace(
        needle,
        replacement,
        1,
    )
    errors = _validate_contract_workflow_text(tmp_path, workflow)
    assert any("script" in error or "command" in error for error in errors)


@pytest.mark.parametrize("contract", [False, True])
@pytest.mark.parametrize(
    "mutation",
    ["nonexistent", "negation", "missing-option", "warn", "ignore"],
)
def test_contract_validator_locks_evidence_artifact_contract(
    tmp_path: Path,
    contract: bool,
    mutation: str,
) -> None:
    source = CONTRACT_WORKFLOW if contract else SECURITY_WORKFLOW
    workflow = source.read_text(encoding="utf-8")
    if contract:
        first_path = "            trivy-frontend-injected.sarif\n"
        second_path = "            trivy-frontend-injected-status.json\n"
    else:
        first_path = "            trivy-backend.sarif\n"
        second_path = "            trivy-frontend.sarif\n"

    if mutation == "nonexistent":
        workflow = workflow.replace(first_path, first_path.replace("            ", "            nonexistent/"), 1)
    elif mutation == "negation":
        workflow = workflow.replace(second_path, f"{second_path}            !ignored.sarif\n", 1)
    elif mutation == "missing-option":
        workflow = workflow.replace("          if-no-files-found: error\n", "", 1)
    else:
        option = f"          if-no-files-found: {mutation}\n"
        if "          if-no-files-found: error\n" in workflow:
            workflow = workflow.replace(
                "          if-no-files-found: error\n",
                option,
                1,
            )
        else:
            workflow = workflow.replace("          retention-days: 30\n", f"          retention-days: 30\n{option}", 1)

    errors = (
        _validate_contract_workflow_text(tmp_path, workflow)
        if contract
        else _validate_workflow_text(tmp_path, workflow)
    )
    assert any("artifact" in error for error in errors)


@pytest.mark.parametrize("contract", [False, True])
@pytest.mark.parametrize(
    "metadata",
    [
        "env:\n  BASH_ENV: /tmp/attacker-env\n",
        "env:\n  PYTHONPATH: /tmp/attacker-python\n",
        "concurrency: attacker-controlled\n",
    ],
)
def test_contract_validator_closes_workflow_execution_metadata(
    tmp_path: Path,
    contract: bool,
    metadata: str,
) -> None:
    source = CONTRACT_WORKFLOW if contract else SECURITY_WORKFLOW
    workflow = source.read_text(encoding="utf-8")
    workflow = workflow.replace("\npermissions:\n", f"\n{metadata}\npermissions:\n", 1)
    errors = (
        _validate_contract_workflow_text(tmp_path, workflow)
        if contract
        else _validate_workflow_text(tmp_path, workflow)
    )
    assert any("workflow" in error and "keys" in error for error in errors)


@pytest.mark.parametrize("contract", [False, True])
@pytest.mark.parametrize(
    "metadata",
    [
        "    env:\n      BASH_ENV: /tmp/attacker-env\n",
        "    env:\n      PYTHONPATH: /tmp/attacker-python\n",
        "    container: attacker/image:latest\n",
        "    services:\n      attacker:\n        image: attacker/service:latest\n",
        "    timeout-minutes: 1\n",
    ],
)
def test_contract_validator_closes_mandatory_job_execution_metadata(
    tmp_path: Path,
    contract: bool,
    metadata: str,
) -> None:
    source = CONTRACT_WORKFLOW if contract else SECURITY_WORKFLOW
    workflow = source.read_text(encoding="utf-8")
    job_name = "injected-finding-contract" if contract else "container-security"
    anchor = f"  {job_name}:\n"
    workflow = workflow.replace(anchor, f"{anchor}{metadata}", 1)
    errors = (
        _validate_contract_workflow_text(tmp_path, workflow)
        if contract
        else _validate_workflow_text(tmp_path, workflow)
    )
    assert any("job" in error and "keys" in error for error in errors)


@pytest.mark.parametrize("contract", [False, True])
def test_contract_validator_requires_approved_runner(
    tmp_path: Path,
    contract: bool,
) -> None:
    source = CONTRACT_WORKFLOW if contract else SECURITY_WORKFLOW
    workflow = source.read_text(encoding="utf-8").replace(
        "    runs-on: ubuntu-latest\n",
        "    runs-on: self-hosted\n",
        1 if contract else 7,
    )
    if not contract:
        original = source.read_text(encoding="utf-8")
        container_anchor = (
            "  container-security:\n"
            "    name: Container Scan (Trivy + SBOM Correlation)\n"
            "    runs-on: ubuntu-latest\n"
        )
        workflow = original.replace(
            container_anchor,
            container_anchor.replace("ubuntu-latest", "self-hosted"),
            1,
        )
    errors = (
        _validate_contract_workflow_text(tmp_path, workflow)
        if contract
        else _validate_workflow_text(tmp_path, workflow)
    )
    assert any("runner" in error for error in errors)


@pytest.mark.parametrize("contract", [False, True])
def test_contract_validator_locks_workflow_permissions(
    tmp_path: Path,
    contract: bool,
) -> None:
    source = CONTRACT_WORKFLOW if contract else SECURITY_WORKFLOW
    workflow = source.read_text(encoding="utf-8")
    anchor = "permissions:\n  contents: read\n"
    workflow = workflow.replace(anchor, f"{anchor}  actions: write\n", 1)
    errors = (
        _validate_contract_workflow_text(tmp_path, workflow)
        if contract
        else _validate_workflow_text(tmp_path, workflow)
    )
    assert any("permissions" in error for error in errors)


def test_contract_validator_parses_exact_injected_workflow_triggers(
    tmp_path: Path,
) -> None:
    workflow = CONTRACT_WORKFLOW.read_text(encoding="utf-8")
    trigger_start = workflow.index("on:\n")
    permissions_start = workflow.index("permissions:\n")
    workflow = (
        workflow[:trigger_start]
        + "on:\n"
        + "  # pull_request:\n"
        + "  # push:\n"
        + "  workflow_dispatch:\n\n"
        + workflow[permissions_start:]
    )
    errors = _validate_contract_workflow_text(tmp_path, workflow)
    assert any("injected-finding" in error and "trigger" in error for error in errors)


def test_contract_validator_requires_immediate_frontend_enforcement(
    tmp_path: Path,
) -> None:
    errors = _validate_workflow_text(
        tmp_path,
        SECURITY_WORKFLOW.read_text(encoding="utf-8"),
    )
    assert not any("unable to load" in error for error in errors)
    assert not any("missing workflow step" in error for error in errors)
    assert not any("immediately" in error for error in errors)

    workflow = SECURITY_WORKFLOW.read_text(encoding="utf-8")
    gate = (
        "      - name: Enforce Frontend Trivy HIGH/CRITICAL Gate\n"
        "        if: always()\n"
        "        run: >-\n"
        "          python3 scripts/security/frontend_trivy_status.py enforce\n"
        "          --status-file trivy-frontend-status.json\n"
    )
    recorder_end = (
        "            --output trivy-frontend-status.json\n"
    )
    without_gate = workflow.replace(f"\n{gate}", "", 1)
    adjacent = without_gate.replace(recorder_end, f"{recorder_end}\n{gate}", 1)
    assert _validate_workflow_text(tmp_path, adjacent) == []


@pytest.mark.parametrize(
    "malicious_step",
    [
        "      - name: Forge frontend status\n"
        "        run: echo '{}' > trivy-frontend-status.json\n",
        "      - uses: attacker/forge-status@0123456789012345678901234567890123456789\n",
    ],
)
def test_contract_validator_rejects_step_between_recorder_and_enforcer(
    tmp_path: Path,
    malicious_step: str,
) -> None:
    workflow = SECURITY_WORKFLOW.read_text(encoding="utf-8")
    recorder_end = "            --output trivy-frontend-status.json\n"
    workflow = workflow.replace(
        recorder_end,
        f"{recorder_end}\n{malicious_step}",
        1,
    )
    errors = _validate_workflow_text(tmp_path, workflow)
    assert any("immediately" in error or "step sequence" in error for error in errors)


def test_production_evidence_uploads_remain_after_blocking_gate(
    tmp_path: Path,
) -> None:
    workflow = SECURITY_WORKFLOW.read_text(encoding="utf-8")
    gate_index = workflow.index("      - name: Enforce Frontend Trivy HIGH/CRITICAL Gate")
    frontend_sarif_index = workflow.index("      - name: Upload Trivy Frontend Report")
    artifact_index = workflow.index("      - name: Upload Container Security Reports")
    assert gate_index < frontend_sarif_index < artifact_index
    assert _validate_workflow_text(tmp_path, workflow) == []


@pytest.mark.parametrize(
    "step_name",
    [
        "Generate Backend SBOM (Syft)",
        "Run Grype on Backend SBOM",
        "Fail on unresolved Grype HIGH/CRITICAL",
    ],
)
def test_backend_security_lane_runs_after_frontend_gate_failure(
    step_name: str,
) -> None:
    workflow = yaml.safe_load(SECURITY_WORKFLOW.read_text(encoding="utf-8"))
    steps = workflow["jobs"]["container-security"]["steps"]
    step = next(item for item in steps if item.get("name") == step_name)
    assert step.get("if") == "always()"


@pytest.mark.parametrize(
    "step_name",
    [
        "Generate Backend SBOM (Syft)",
        "Run Grype on Backend SBOM",
        "Fail on unresolved Grype HIGH/CRITICAL",
    ],
)
def test_contract_validator_locks_backend_security_lane_independence(
    tmp_path: Path,
    step_name: str,
) -> None:
    workflow = SECURITY_WORKFLOW.read_text(encoding="utf-8")
    anchor = f"      - name: {step_name}\n        if: always()\n"
    assert anchor in workflow
    workflow = workflow.replace(anchor, anchor.replace("always()", "false"), 1)
    errors = _validate_workflow_text(tmp_path, workflow)
    assert any("backend" in error and "always" in error for error in errors)


@pytest.mark.parametrize("contract", [False, True])
@pytest.mark.parametrize("mutation", ["missing", "noop", "partial"])
def test_contract_validator_requires_each_artifact_evidence_file(
    tmp_path: Path,
    contract: bool,
    mutation: str,
) -> None:
    source = CONTRACT_WORKFLOW if contract else SECURITY_WORKFLOW
    workflow = source.read_text(encoding="utf-8")
    if contract:
        verifier = (
            "      - name: Verify injected-finding evidence files\n"
            "        if: always()\n"
            "        run: |\n"
            "          set -euo pipefail\n"
            "          test -f trivy-frontend-injected.sarif\n"
            "          test -f trivy-frontend-injected-status.json\n"
        )
        required_line = "          test -f trivy-frontend-injected-status.json\n"
    else:
        verifier = (
            "      - name: Verify Container Security Evidence Files\n"
            "        if: always()\n"
            "        run: |\n"
            "          set -euo pipefail\n"
            "          test -f trivy-backend.sarif\n"
            "          test -f trivy-frontend.sarif\n"
            "          test -f trivy-frontend-status.json\n"
            "          test -f sbom-backend.json\n"
            "          test -f grype-backend.json\n"
        )
        required_line = "          test -f trivy-frontend-status.json\n"

    assert verifier in workflow
    if mutation == "missing":
        workflow = workflow.replace(f"\n{verifier}", "", 1)
    elif mutation == "noop":
        workflow = workflow.replace(
            required_line,
            required_line.replace("test -f", "echo test -f"),
            1,
        )
    else:
        workflow = workflow.replace(required_line, "", 1)

    errors = (
        _validate_contract_workflow_text(tmp_path, workflow)
        if contract
        else _validate_workflow_text(tmp_path, workflow)
    )
    assert any("evidence file verifier" in error or "step sequence" in error for error in errors)


@pytest.mark.parametrize(
    "mutation",
    [
        "echo",
        "action",
        "sarif-file",
        "category",
        "continue-false",
        "continue-expression",
        "continue-missing",
        "extra-metadata",
    ],
)
def test_contract_validator_locks_frontend_code_scanning_upload(
    tmp_path: Path,
    mutation: str,
) -> None:
    workflow = SECURITY_WORKFLOW.read_text(encoding="utf-8")
    original = (
        "      - name: Upload Trivy Frontend Report\n"
        "        if: always()\n"
        "        uses: github/codeql-action/upload-sarif@7211b7c8077ea37d8641b6271f6a365a22a5fbfa # v4.36.0\n"
        "        with:\n"
        "          sarif_file: 'trivy-frontend.sarif'\n"
        "          category: 'trivy-frontend'\n"
        "        continue-on-error: true\n"
    )
    assert original in workflow
    mutated = original
    if mutation == "echo":
        mutated = mutated.replace(
            "        uses: github/codeql-action/upload-sarif@7211b7c8077ea37d8641b6271f6a365a22a5fbfa # v4.36.0\n",
            "        run: echo upload trivy-frontend.sarif\n",
        )
    elif mutation == "action":
        mutated = mutated.replace(
            "github/codeql-action/upload-sarif@7211b7c8077ea37d8641b6271f6a365a22a5fbfa",
            "attacker/upload-sarif@0123456789012345678901234567890123456789",
        )
    elif mutation == "sarif-file":
        mutated = mutated.replace("trivy-frontend.sarif", "nonexistent.sarif")
    elif mutation == "category":
        mutated = mutated.replace("category: 'trivy-frontend'", "category: 'other'")
    elif mutation == "continue-false":
        mutated = mutated.replace("continue-on-error: true", "continue-on-error: false")
    elif mutation == "continue-expression":
        mutated = mutated.replace(
            "continue-on-error: true",
            'continue-on-error: "${{ true }}"',
        )
    elif mutation == "continue-missing":
        mutated = mutated.replace("        continue-on-error: true\n", "")
    else:
        mutated = mutated.replace(
            "        if: always()\n",
            "        if: always()\n        working-directory: /tmp\n",
        )

    errors = _validate_workflow_text(tmp_path, workflow.replace(original, mutated, 1))
    assert any("frontend SARIF upload" in error for error in errors)


@pytest.mark.parametrize(
    "mutation",
    [
        "overwrite-run",
        "action",
        "sarif-file",
        "category",
        "if",
        "continue-false",
        "continue-expression",
        "continue-missing",
        "extra-metadata",
    ],
)
def test_contract_validator_locks_backend_code_scanning_upload(
    tmp_path: Path,
    mutation: str,
) -> None:
    workflow = SECURITY_WORKFLOW.read_text(encoding="utf-8")
    original = (
        "      - name: Upload Trivy Backend Report\n"
        "        if: always()\n"
        "        uses: github/codeql-action/upload-sarif@7211b7c8077ea37d8641b6271f6a365a22a5fbfa # v4.36.0\n"
        "        with:\n"
        "          sarif_file: 'trivy-backend.sarif'\n"
        "          category: 'trivy-backend'\n"
        "        continue-on-error: true\n"
    )
    assert original in workflow
    mutated = original
    if mutation == "overwrite-run":
        mutated = (
            "      - name: Upload Trivy Backend Report\n"
            "        if: always()\n"
            "        run: |\n"
            "          echo '{}' > trivy-frontend.sarif\n"
            "          echo '{}' > trivy-frontend-status.json\n"
        )
    elif mutation == "action":
        mutated = mutated.replace(
            "github/codeql-action/upload-sarif@7211b7c8077ea37d8641b6271f6a365a22a5fbfa",
            "attacker/upload-sarif@0123456789012345678901234567890123456789",
        )
    elif mutation == "sarif-file":
        mutated = mutated.replace("trivy-backend.sarif", "trivy-frontend.sarif")
    elif mutation == "category":
        mutated = mutated.replace("category: 'trivy-backend'", "category: 'other'")
    elif mutation == "if":
        mutated = mutated.replace("if: always()", "if: false")
    elif mutation == "continue-false":
        mutated = mutated.replace("continue-on-error: true", "continue-on-error: false")
    elif mutation == "continue-expression":
        mutated = mutated.replace(
            "continue-on-error: true",
            'continue-on-error: "${{ true }}"',
        )
    elif mutation == "continue-missing":
        mutated = mutated.replace("        continue-on-error: true\n", "")
    else:
        mutated = mutated.replace(
            "        if: always()\n",
            "        if: always()\n        env:\n          BASH_ENV: /tmp/attacker\n",
        )

    errors = _validate_workflow_text(tmp_path, workflow.replace(original, mutated, 1))
    assert any("backend SARIF upload" in error for error in errors)
