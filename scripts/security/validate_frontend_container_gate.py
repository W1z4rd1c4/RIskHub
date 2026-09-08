#!/usr/bin/env python3
"""Validate the frontend container vulnerability gate and its workflow proof."""

from __future__ import annotations

import hashlib
import re
import sys
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
WORKFLOW_PATH = REPO_ROOT / ".github/workflows/security.yml"
CONTRACT_WORKFLOW_PATH = (
    REPO_ROOT / ".github/workflows/frontend-container-gate-contract.yml"
)
STATUS_HELPER = REPO_ROOT / "scripts/security/frontend_trivy_status.py"
SARIF_SCHEMA_URI = (
    "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/"
    "schemas/sarif-schema-2.1.0.json"
)
DEFAULT_TRIVY_PATHS = (".trivyignore", "trivy.yaml")
APPROVED_PRODUCTION_TRIGGERS = {
    "push": {"branches": ["main", "develop"]},
    "pull_request": {"branches": ["main", "develop", "feat/identity-group-*"]},
    "schedule": [
        {"cron": "0 2 * * *"},
        {"cron": "0 0 * * 0"},
    ],
}
INJECTED_TRIGGER_PATHS = [
    ".github/workflows/frontend-container-gate-contract.yml",
    ".github/workflows/security.yml",
    "scripts/security/frontend_trivy_status.py",
    "scripts/security/validate_frontend_container_gate.py",
    "tests/backend/pytest/test_frontend_container_security_contract.py",
]
APPROVED_INJECTED_TRIGGERS = {
    "pull_request": {
        "branches": ["main", "develop", "feat/identity-group-*"],
        "paths": INJECTED_TRIGGER_PATHS,
    },
    "push": {
        "branches": ["main", "develop"],
        "paths": INJECTED_TRIGGER_PATHS,
    },
    "workflow_dispatch": None,
}
EXPECTED_PRODUCTION_STEP_NAMES = [
    None,
    "Build Backend Image",
    "Build Frontend Image",
    "Run Trivy on Backend",
    "Run Trivy on Frontend",
    "Record Frontend Trivy Scan Status",
    "Enforce Frontend Trivy HIGH/CRITICAL Gate",
    "Generate Backend SBOM (Syft)",
    "Run Grype on Backend SBOM",
    "Fail on unresolved Grype HIGH/CRITICAL",
    "Upload Trivy Backend Report",
    "Upload Trivy Frontend Report",
    "Verify Container Security Evidence Files",
    "Upload Container Security Reports",
]
EXPECTED_BACKEND_RUN_STEP_SHA256 = {
    "Generate Backend SBOM (Syft)": (
        "ae9295934d17a536ae24b81c81c829558185af8ec4a79cdb652d9a750fa817ed"
    ),
    "Run Grype on Backend SBOM": (
        "9f338d28ee2b06c06246a06c591207539ae7372d020f677291093e51a1c61035"
    ),
    "Fail on unresolved Grype HIGH/CRITICAL": (
        "168646568c5ce6ce70ecab7051066616e1b1a6ea9f4a54e45e9250be11689edb"
    ),
}
EXPECTED_STATUS_RECORD_COMMAND = (
    'python3 scripts/security/frontend_trivy_status.py record '
    '--outcome "$FRONTEND_TRIVY_OUTCOME" '
    "--sarif trivy-frontend.sarif "
    "--output trivy-frontend-status.json"
)
EXPECTED_ENFORCEMENT_COMMAND = (
    "python3 scripts/security/frontend_trivy_status.py enforce "
    "--status-file trivy-frontend-status.json"
)
UPLOAD_ARTIFACT_ACTION = (
    "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a"
)
UPLOAD_SARIF_ACTION = (
    "github/codeql-action/upload-sarif@7211b7c8077ea37d8641b6271f6a365a22a5fbfa"
)
EXPECTED_PRODUCTION_ARTIFACT_PATHS = frozenset(
    {
        "trivy-backend.sarif",
        "trivy-frontend.sarif",
        "trivy-frontend-status.json",
        "sbom-backend.json",
        "grype-backend.json",
    }
)
EXPECTED_INJECTED_ARTIFACT_PATHS = frozenset(
    {
        "trivy-frontend-injected.sarif",
        "trivy-frontend-injected-status.json",
    }
)
EXPECTED_INJECTED_GENERATOR_SHA256 = (
    "4fedc40cf6e7a5590c897b8ceaff4e25dc2450641d47d8a748d64d15725b8d62"
)
EXPECTED_INJECTED_PROOF_SHA256 = (
    "8fba6415b4b235b2db594283ac2f21accbf481a48c2235b218ee82b6e8ece8be"
)
EXPECTED_INJECTED_RECORD_COMMAND = (
    "python3 scripts/security/frontend_trivy_status.py record "
    "--outcome success "
    "--sarif trivy-frontend-injected.sarif "
    "--output trivy-frontend-injected-status.json"
)
EXPECTED_PRODUCTION_EVIDENCE_VERIFIER_SHA256 = (
    "2a8ef03c72faed256ccd285e192960b789c968b8dd46fde973b7628be1ebc476"
)
EXPECTED_INJECTED_EVIDENCE_VERIFIER_SHA256 = (
    "8f560b30e108f5b52b1be9879f12d3673425e57102a8307db6d9613a52ed245d"
)


def _step_by_name(steps: list[dict], name: str) -> tuple[int, dict]:
    for index, step in enumerate(steps):
        if step.get("name") == name:
            return index, step
    raise ValueError(f"missing workflow step: {name}")


def _load_yaml(path: Path) -> dict:
    payload = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"{path.name} must contain a workflow object")
    return payload


def _reject_continue_on_error(errors: list[str], subject: str, node: dict) -> None:
    if "continue-on-error" in node and node.get("continue-on-error") is not False:
        errors.append(
            f"{subject} must remain blocking; continue-on-error expressions/true are forbidden"
        )


def _reject_run_defaults(errors: list[str], subject: str, node: dict) -> None:
    if "defaults" in node:
        errors.append(f"{subject} must not define defaults affecting run steps")


def _require_exact_keys(
    errors: list[str],
    subject: str,
    node: dict,
    expected: set[str],
) -> None:
    if set(node) != expected:
        errors.append(
            f"{subject} keys must be exactly {', '.join(sorted(expected))}"
        )


def _workflow_keys(workflow: dict) -> set[str]:
    return {"on" if key is True else str(key) for key in workflow}


def _validate_workflow_schema(
    errors: list[str],
    subject: str,
    workflow: dict,
    *,
    expected_permissions: dict[str, str],
) -> None:
    expected_keys = {"name", "on", "permissions", "jobs"}
    if _workflow_keys(workflow) != expected_keys:
        errors.append(
            f"{subject} keys must be exactly {', '.join(sorted(expected_keys))}"
        )
    if workflow.get("permissions") != expected_permissions:
        errors.append(f"{subject} permissions must match exactly")


def _validate_mandatory_job_schema(
    errors: list[str],
    subject: str,
    job: dict,
    *,
    expected_name: str,
) -> None:
    _require_exact_keys(errors, subject, job, {"name", "runs-on", "steps"})
    if job.get("name") != expected_name:
        errors.append(f"{subject} name must match exactly")
    if job.get("runs-on") != "ubuntu-latest":
        errors.append(f"{subject} runner must be ubuntu-latest")


def _normalize_run_command(command: object) -> str:
    if not isinstance(command, str):
        return ""
    return " ".join(command.replace("\\\n", " ").split())


def _script_sha256(script: object) -> str:
    if not isinstance(script, str):
        return ""
    return hashlib.sha256(script.encode("utf-8")).hexdigest()


def _artifact_paths(value: object) -> tuple[str, ...]:
    if not isinstance(value, str):
        return ()
    return tuple(line.strip() for line in value.splitlines() if line.strip())


def _validate_artifact_upload(
    errors: list[str],
    subject: str,
    step: dict,
    *,
    expected_name: str,
    expected_paths: frozenset[str],
) -> None:
    _require_exact_keys(errors, subject, step, {"name", "if", "uses", "with"})
    if step.get("if") != "always()":
        errors.append(f"{subject} must run with if: always()")
    if step.get("uses") != UPLOAD_ARTIFACT_ACTION:
        errors.append(f"{subject} must use the approved upload-artifact action")

    options = step.get("with")
    if not isinstance(options, dict):
        errors.append(f"{subject} artifact inputs must be a mapping")
        return
    expected_keys = {"name", "path", "retention-days", "if-no-files-found"}
    if set(options) != expected_keys:
        errors.append(f"{subject} artifact input keys must match exactly")
    if options.get("name") != expected_name:
        errors.append(f"{subject} artifact name must be {expected_name!r}")
    paths = _artifact_paths(options.get("path"))
    if len(paths) != len(expected_paths) or frozenset(paths) != expected_paths:
        errors.append(f"{subject} artifact paths must match exactly")
    if options.get("retention-days") != 30:
        errors.append(f"{subject} artifact retention must remain 30 days")
    if options.get("if-no-files-found") != "error":
        errors.append(f"{subject} artifact must fail when files are missing")


def _validate_sarif_upload(
    errors: list[str],
    step: dict,
    *,
    subject: str,
    sarif_file: str,
    category: str,
) -> None:
    _require_exact_keys(
        errors,
        subject,
        step,
        {"name", "if", "uses", "with", "continue-on-error"},
    )
    if step.get("if") != "always()":
        errors.append(f"{subject} must run with if: always()")
    if step.get("uses") != UPLOAD_SARIF_ACTION:
        errors.append(f"{subject} must use the approved upload-sarif action")
    if step.get("with") != {
        "sarif_file": sarif_file,
        "category": category,
    }:
        errors.append(f"{subject} inputs must match exactly")
    if step.get("continue-on-error") is not True:
        errors.append(f"{subject} continue-on-error policy must remain literal true")


def _validate_pre_scan_steps(
    errors: list[str],
    steps: list[dict],
    scan_index: int,
) -> None:
    expected = [
        {
            "uses": "actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd",
            "with": {"ref": "${{ github.event.pull_request.head.sha || github.sha }}"},
        },
        {
            "name": "Build Backend Image",
            "run": "docker build -t riskhub-backend:scan -f backend/Dockerfile backend/",
        },
        {
            "name": "Build Frontend Image",
            "run": "docker build -t riskhub-frontend:scan -f frontend/Dockerfile frontend/",
        },
        {
            "name": "Run Trivy on Backend",
            "uses": "aquasecurity/trivy-action@ed142fd0673e97e23eac54620cfb913e5ce36c25",
            "with": {
                "image-ref": "riskhub-backend:scan",
                "format": "sarif",
                "output": "trivy-backend.sarif",
                "severity": "CRITICAL,HIGH",
            },
        },
    ]
    actual = steps[:scan_index]
    if len(actual) != len(expected):
        errors.append("production pre-scan step sequence must match exactly")
        return
    for index, (step, approved) in enumerate(zip(actual, expected, strict=True)):
        normalized = dict(step)
        if "run" in normalized:
            normalized["run"] = _normalize_run_command(normalized["run"])
        if normalized != approved:
            errors.append(
                f"production pre-scan step {index + 1} must match exactly; "
                "TRIVY_ and GITHUB_ENV injection is forbidden"
            )


def _validate_production_triggers(workflow: dict) -> list[str]:
    errors: list[str] = []
    triggers = workflow.get("on", workflow.get(True))
    if not isinstance(triggers, dict):
        return ["production security workflow must define trigger mappings"]

    for name, approved in APPROVED_PRODUCTION_TRIGGERS.items():
        if name not in triggers:
            errors.append(f"production security workflow must define {name} trigger")
        elif triggers[name] != approved:
            requirement = " including main" if name == "push" else ""
            errors.append(
                f"production {name} trigger must match the approved configuration"
                f"{requirement}"
            )

    unexpected = set(triggers) - set(APPROVED_PRODUCTION_TRIGGERS)
    if unexpected:
        errors.append(
            "production security workflow has unapproved triggers: "
            + ", ".join(sorted(str(name) for name in unexpected))
        )
    return errors


def _reject_trivy_environment_overrides(
    errors: list[str],
    subject: str,
    node: dict,
) -> None:
    environment = node.get("env")
    if environment is None:
        return
    if not isinstance(environment, dict):
        errors.append(f"{subject} env must be a mapping without Trivy overrides")
        return
    for name in environment:
        if str(name).upper().startswith("TRIVY_"):
            errors.append(f"{subject} must not set Trivy override {name!r}")


def _validate_injected_finding_workflow() -> list[str]:
    errors: list[str] = []
    if not CONTRACT_WORKFLOW_PATH.is_file():
        return ["missing injected-finding workflow proof"]

    try:
        workflow = _load_yaml(CONTRACT_WORKFLOW_PATH)
        jobs = workflow["jobs"]
        job = jobs["injected-finding-contract"]
        steps = job["steps"]
    except (OSError, KeyError, TypeError, ValueError, yaml.YAMLError) as exc:
        return [*errors, f"unable to load injected-finding workflow: {exc}"]

    _validate_workflow_schema(
        errors,
        "injected-finding workflow",
        workflow,
        expected_permissions={"contents": "read"},
    )
    triggers = workflow.get("on", workflow.get(True))
    if triggers != APPROVED_INJECTED_TRIGGERS:
        errors.append("injected-finding workflow triggers must match exactly")
    if not isinstance(jobs, dict) or set(jobs) != {"injected-finding-contract"}:
        errors.append("injected-finding workflow jobs must match exactly")
    _validate_mandatory_job_schema(
        errors,
        "injected-finding contract job",
        job,
        expected_name="Frontend Container Injected Finding Contract",
    )
    _reject_run_defaults(errors, "injected-finding workflow", workflow)
    _reject_run_defaults(errors, "injected-finding contract job", job)
    _reject_continue_on_error(errors, "injected-finding contract job", job)
    if "if" in job:
        errors.append("injected-finding contract job must not be conditional")
    if "needs" in job:
        errors.append("injected-finding contract job must not declare needs")

    expected_step_names = [
        None,
        "Set up Python",
        "Install pinned workflow parser",
        "Generate injected Trivy SARIF finding",
        "Record injected frontend finding",
        "Prove injected finding is blocked",
        "Validate production workflow contract",
        "Verify injected-finding evidence files",
        "Upload injected-finding evidence",
    ]
    if [step.get("name") for step in steps] != expected_step_names:
        errors.append("injected-finding step sequence must match exactly")

    expected_checkout = {
        "uses": "actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd",
        "with": {"ref": "${{ github.event.pull_request.head.sha || github.sha }}"},
    }
    if not steps or steps[0] != expected_checkout:
        errors.append("injected-finding checkout step must match exactly")
    expected_setup = {
        "name": "Set up Python",
        "uses": "actions/setup-python@a309ff8b426b58ec0e2a45f0f869d46889d02405",
        "with": {"python-version": "3.13"},
    }
    if len(steps) < 2 or steps[1] != expected_setup:
        errors.append("injected-finding Python setup step must match exactly")
    if len(steps) < 3:
        errors.append("injected-finding parser install step is missing")
    else:
        parser_install = steps[2]
        _require_exact_keys(
            errors,
            "injected-finding parser install step",
            parser_install,
            {"name", "run"},
        )
        if _normalize_run_command(parser_install.get("run")) != (
            "python3 -m pip install PyYAML==6.0.3"
        ):
            errors.append("injected-finding parser install command must match exactly")

    try:
        generated_index, generated = _step_by_name(
            steps,
            "Generate injected Trivy SARIF finding",
        )
        recorded_index, recorded = _step_by_name(
            steps,
            "Record injected frontend finding",
        )
        proof_index, proved = _step_by_name(steps, "Prove injected finding is blocked")
        validation_index, validated = _step_by_name(
            steps,
            "Validate production workflow contract",
        )
        verifier_index, evidence_verifier = _step_by_name(
            steps,
            "Verify injected-finding evidence files",
        )
        upload_index, evidence_upload = _step_by_name(
            steps,
            "Upload injected-finding evidence",
        )
    except ValueError as exc:
        return [*errors, str(exc)]

    for step_name, step in (
        ("injected SARIF generator", generated),
        ("injected-finding recorder", recorded),
        ("injected-finding blocking proof", proved),
        ("production-contract validation", validated),
        ("injected evidence file verifier", evidence_verifier),
        ("injected evidence upload", evidence_upload),
    ):
        _reject_continue_on_error(errors, step_name, step)

    for subject, step in (
        ("injected SARIF generator", generated),
        ("injected-finding recorder", recorded),
        ("injected-finding blocking proof", proved),
        ("production-contract validation", validated),
    ):
        _require_exact_keys(errors, subject, step, {"name", "run"})

    if _script_sha256(generated.get("run")) != EXPECTED_INJECTED_GENERATOR_SHA256:
        errors.append("injected SARIF generator script must match exactly")
    if _normalize_run_command(recorded.get("run")) != EXPECTED_INJECTED_RECORD_COMMAND:
        errors.append("injected-finding recorder command must match exactly")
    if _script_sha256(proved.get("run")) != EXPECTED_INJECTED_PROOF_SHA256:
        errors.append("injected-finding blocking proof script must match exactly")
    if _normalize_run_command(validated.get("run")) != (
        "python3 scripts/security/validate_frontend_container_gate.py"
    ):
        errors.append("production-contract validation command must match exactly")
    _require_exact_keys(
        errors,
        "injected evidence file verifier",
        evidence_verifier,
        {"name", "if", "run"},
    )
    if evidence_verifier.get("if") != "always()":
        errors.append("injected evidence file verifier must run with if: always()")
    if (
        _script_sha256(evidence_verifier.get("run"))
        != EXPECTED_INJECTED_EVIDENCE_VERIFIER_SHA256
    ):
        errors.append("injected evidence file verifier script must match exactly")

    _validate_artifact_upload(
        errors,
        "injected evidence artifact",
        evidence_upload,
        expected_name="frontend-container-injected-finding-evidence",
        expected_paths=EXPECTED_INJECTED_ARTIFACT_PATHS,
    )

    if not (
        generated_index
        < recorded_index
        < proof_index
        < validation_index
        < verifier_index
        < upload_index
    ):
        errors.append(
            "injected evidence must be generated, recorded, rejected, validated, and uploaded in order"
        )
    if upload_index != verifier_index + 1:
        errors.append("injected evidence file verifier must immediately precede upload")
    return errors


def validate() -> list[str]:
    errors = _validate_injected_finding_workflow()

    for relative_path in DEFAULT_TRIVY_PATHS:
        if (REPO_ROOT / relative_path).is_file():
            errors.append(
                f"default Trivy configuration path {relative_path} is forbidden"
            )

    if not STATUS_HELPER.is_file():
        errors.append("missing frontend Trivy status recorder/enforcer")
    else:
        helper_text = STATUS_HELPER.read_text(encoding="utf-8")
        for required_text in (
            "SARIF_SCHEMA_URI",
            "HOSTED_TRIVY_V070_SCHEMA_URI",
            "ACCEPTED_SARIF_SCHEMA_URIS",
            "TRIVY_DRIVER_FULL_NAME",
            "TRIVY_INFORMATION_URI",
            "KNOWN_SEVERITIES",
            "QUALIFYING_SEVERITIES",
            "REQUIRED_STATUS_FIELDS",
            "sarif_sha256",
            "_trivy_rules",
            "sarif_nonqualifying_result",
            "status evidence has unknown fields",
            "_status_errors",
        ):
            if required_text not in helper_text:
                errors.append(
                    f"frontend Trivy status helper is missing: {required_text}"
                )

    try:
        workflow = _load_yaml(WORKFLOW_PATH)
        container_job = workflow["jobs"]["container-security"]
        steps = container_job["steps"]
    except (OSError, KeyError, TypeError, ValueError, yaml.YAMLError) as exc:
        return [*errors, f"unable to load container-security workflow: {exc}"]

    errors.extend(_validate_production_triggers(workflow))
    _validate_workflow_schema(
        errors,
        "production security workflow",
        workflow,
        expected_permissions={"contents": "read", "security-events": "write"},
    )
    _validate_mandatory_job_schema(
        errors,
        "production container-security job",
        container_job,
        expected_name="Container Scan (Trivy + SBOM Correlation)",
    )
    _reject_run_defaults(errors, "production security workflow", workflow)
    _reject_run_defaults(errors, "production container-security job", container_job)
    _reject_continue_on_error(errors, "production container-security job", container_job)
    if "if" in container_job:
        errors.append("production container-security job must not be conditional")
    if "needs" in container_job:
        errors.append("production container-security job must not declare needs")
    _reject_trivy_environment_overrides(errors, "production workflow", workflow)
    _reject_trivy_environment_overrides(
        errors,
        "production container-security job",
        container_job,
    )
    if [step.get("name") for step in steps] != EXPECTED_PRODUCTION_STEP_NAMES:
        errors.append("production container-security step sequence must match exactly")

    try:
        scan_index, scan = _step_by_name(steps, "Run Trivy on Frontend")
        status_index, status_record = _step_by_name(
            steps,
            "Record Frontend Trivy Scan Status",
        )
        sarif_index, sarif_upload = _step_by_name(
            steps,
            "Upload Trivy Frontend Report",
        )
        _, backend_sarif_upload = _step_by_name(
            steps,
            "Upload Trivy Backend Report",
        )
        artifact_index, artifact_upload = _step_by_name(
            steps,
            "Upload Container Security Reports",
        )
        verifier_index, evidence_verifier = _step_by_name(
            steps,
            "Verify Container Security Evidence Files",
        )
        gate_index, gate = _step_by_name(
            steps,
            "Enforce Frontend Trivy HIGH/CRITICAL Gate",
        )
        backend_steps = {
            name: _step_by_name(steps, name)[1]
            for name in EXPECTED_BACKEND_RUN_STEP_SHA256
        }
    except ValueError as exc:
        return [*errors, str(exc)]

    _validate_pre_scan_steps(errors, steps, scan_index)
    _require_exact_keys(
        errors,
        "frontend Trivy scan step",
        scan,
        {"name", "id", "continue-on-error", "uses", "with"},
    )
    if scan.get("id") != "trivy_frontend":
        errors.append("frontend Trivy scan must expose id=trivy_frontend")
    if scan.get("continue-on-error") is not True:
        errors.append(
            "frontend Trivy scan must continue temporarily so reports can upload"
        )

    action = str(scan.get("uses", ""))
    if not re.fullmatch(r"aquasecurity/trivy-action@[0-9a-f]{40}", action):
        errors.append("frontend Trivy action must remain pinned to a full commit SHA")

    _reject_trivy_environment_overrides(errors, "frontend Trivy scan", scan)

    options = scan.get("with", {})
    if not isinstance(options, dict):
        errors.append("frontend Trivy inputs must be a mapping")
        options = {}
    expected_options = {
        "image-ref": "riskhub-frontend:scan",
        "format": "sarif",
        "output": "trivy-frontend.sarif",
        "scanners": "vuln",
        "severity": "CRITICAL,HIGH",
        "exit-code": "1",
        "limit-severities-for-sarif": True,
    }
    for key, expected in expected_options.items():
        if options.get(key) != expected:
            errors.append(
                f"frontend Trivy option {key!r} must be {expected!r}, "
                f"got {options.get(key)!r}"
            )
    for key in sorted(set(options) - set(expected_options)):
        errors.append(f"frontend Trivy option {key!r} is not allowed")
    if "ignore-unfixed" in options:
        errors.append("frontend Trivy gate must not set ignore-unfixed")

    _require_exact_keys(
        errors,
        "frontend scan-status recorder step",
        status_record,
        {"name", "if", "env", "run"},
    )
    if status_record.get("if") != "always()":
        errors.append("frontend scan-status recorder must run with if: always()")
    _reject_continue_on_error(errors, "frontend scan-status recorder", status_record)
    status_env = status_record.get("env", {})
    expected_status_env = {
        "FRONTEND_TRIVY_OUTCOME": "${{ steps.trivy_frontend.outcome }}"
    }
    if status_env != expected_status_env:
        errors.append("frontend scan-status recorder must consume the raw scan outcome")
    status_script = _normalize_run_command(status_record.get("run"))
    if status_script != EXPECTED_STATUS_RECORD_COMMAND:
        errors.append("frontend scan-status recorder command must match exactly")

    _validate_sarif_upload(
        errors,
        sarif_upload,
        subject="frontend SARIF upload",
        sarif_file="trivy-frontend.sarif",
        category="trivy-frontend",
    )
    _validate_sarif_upload(
        errors,
        backend_sarif_upload,
        subject="backend SARIF upload",
        sarif_file="trivy-backend.sarif",
        category="trivy-backend",
    )

    _require_exact_keys(
        errors,
        "production evidence file verifier",
        evidence_verifier,
        {"name", "if", "run"},
    )
    if evidence_verifier.get("if") != "always()":
        errors.append("production evidence file verifier must run with if: always()")
    if (
        _script_sha256(evidence_verifier.get("run"))
        != EXPECTED_PRODUCTION_EVIDENCE_VERIFIER_SHA256
    ):
        errors.append("production evidence file verifier script must match exactly")

    _validate_artifact_upload(
        errors,
        "container report artifact",
        artifact_upload,
        expected_name="container-security-reports",
        expected_paths=EXPECTED_PRODUCTION_ARTIFACT_PATHS,
    )

    _require_exact_keys(
        errors,
        "frontend enforcement step",
        gate,
        {"name", "if", "run"},
    )
    if gate.get("if") != "always()":
        errors.append("frontend enforcement step must run with if: always()")
    _reject_continue_on_error(errors, "frontend enforcement step", gate)
    gate_script = _normalize_run_command(gate.get("run"))
    if gate_script != EXPECTED_ENFORCEMENT_COMMAND:
        errors.append("frontend enforcement command must match exactly")

    for name, expected_digest in EXPECTED_BACKEND_RUN_STEP_SHA256.items():
        backend_step = backend_steps[name]
        subject = f"backend security step {name!r}"
        _require_exact_keys(errors, subject, backend_step, {"name", "if", "run"})
        if backend_step.get("if") != "always()":
            errors.append(f"{subject} must run with if: always()")
        if _script_sha256(backend_step.get("run")) != expected_digest:
            errors.append(f"{subject} script must match exactly")

    if status_index != scan_index + 1:
        errors.append("frontend status must be recorded immediately after the scan")
    if gate_index != status_index + 1:
        errors.append("frontend enforcement must run immediately after status recording")
    if not (gate_index < sarif_index < verifier_index < artifact_index):
        errors.append(
            "frontend evidence uploads must remain after the blocking enforcement step"
        )
    if artifact_index != verifier_index + 1:
        errors.append("production evidence file verifier must immediately precede upload")

    return errors


def main() -> int:
    errors = validate()
    if errors:
        for error in errors:
            print(f"frontend-container-gate error: {error}", file=sys.stderr)
        return 1
    print("Frontend container vulnerability gate: valid")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
