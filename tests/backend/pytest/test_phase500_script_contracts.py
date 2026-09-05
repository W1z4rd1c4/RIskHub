"""Contract checks for retained and retired production script behavior."""

from __future__ import annotations

import json
import os
import re
import shlex
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[3]
PROD_SCRIPTS_DIR = REPO_ROOT / "scripts" / "prod"
PROD_PREFLIGHT_LIB = PROD_SCRIPTS_DIR / "lib" / "preflight.sh"
BACKEND_RUNTIME_PROD = REPO_ROOT / "backend" / "scripts" / "runtime" / "prod.sh"
BACKEND_DB_RUNTIME_PROD = (
    REPO_ROOT / "backend" / "scripts" / "runtime" / "db" / "prod.sh"
)
FRONTEND_RUNTIME_PROD = REPO_ROOT / "frontend" / "scripts" / "runtime" / "prod.sh"
BACKEND_DOCKERFILE = REPO_ROOT / "backend" / "Dockerfile"
LINUX_BUNDLE_BUILDER = REPO_ROOT / "scripts" / "release" / "build_linux_bundle.sh"
RELEASE_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "release.yml"
MAKEFILE = REPO_ROOT / "scripts" / "Makefile"
DEV_COMPOSE = REPO_ROOT / "docker-compose.yml"
RELEASE_PARITY_AUDIT_DIR = REPO_ROOT / "scripts" / "security" / "release_parity_audit"
RELEASE_PARITY_AUDIT_RUNTIME = RELEASE_PARITY_AUDIT_DIR / "runtime.py"
FRONTEND_DOCKERFILE = REPO_ROOT / "frontend" / "Dockerfile"
GRYPE_IGNORE = REPO_ROOT / "backend" / "security" / "grype-ignore.yaml"
PROD_READINESS_AUDIT_CONSTRAINTS = (
    REPO_ROOT / "backend" / "requirements-prod-readiness-audit-constraints.txt"
)
SECURITY_SCRIPTS_DIR = REPO_ROOT / "scripts" / "security"
EXPECTED_PROD_BOOTSTRAP_SCRIPTS = (
    "__init__.py",
    "bootstrap_sso_user.py",
    "revoke_refresh_sessions.py",
    "seed_departments.py",
    "seed_roles_permissions.py",
)
ACTIVE_DOCS = [
    REPO_ROOT / "AGENTS.md",
    REPO_ROOT / "docs" / "deployment" / "README.md",
    REPO_ROOT / "docs" / "deployment" / "advanced.md",
    REPO_ROOT / "docs" / "deployment" / "production.md",
    REPO_ROOT / "docs" / "deployment" / "reference.md",
    REPO_ROOT / "docs" / "deployment" / "security-checklist.md",
    REPO_ROOT / "docs" / "agent" / "README.md",
    REPO_ROOT / "docs" / "agent" / "AGENTS_DOC_COVERAGE.md",
    REPO_ROOT / ".planning" / "PROJECT.md",
    REPO_ROOT / ".planning" / "STATE.md",
    REPO_ROOT / ".planning" / "codebase" / "STRUCTURE.md",
    REPO_ROOT / ".planning" / "codebase" / "ARCHITECTURE.md",
    REPO_ROOT / ".planning" / "codebase" / "INTEGRATIONS.md",
    REPO_ROOT / ".planning" / "codebase" / "STACK.md",
    REPO_ROOT / "scripts" / "README.md",
    REPO_ROOT / "scripts" / "prod" / "README.md",
    REPO_ROOT / "scripts" / "prod" / "config" / "README.md",
    REPO_ROOT / "scripts" / "prod" / "config" / "backend.env.example",
    REPO_ROOT / "scripts" / "prod" / "config" / "frontend.env.example",
]
REMOVED_DEPLOYMENT_ARTIFACTS = [
    REPO_ROOT / "docs" / "deployment" / "docker-compose-prod.md",
    REPO_ROOT / "docs" / "deployment" / "kubernetes.md",
    REPO_ROOT / "docs" / "deployment" / "installation-manual.md",
    REPO_ROOT / "docs" / "deployment" / "external-postgres-install-scripts.md",
    REPO_ROOT / "docs" / "deployment" / "component-runtime-entrypoints.md",
    REPO_ROOT / "scripts" / "prod" / "setup.sh",
    REPO_ROOT / "scripts" / "prod" / "deploy.sh",
    REPO_ROOT / "scripts" / "prod" / "upgrade.sh",
    REPO_ROOT / "scripts" / "prod" / "stop.sh",
    REPO_ROOT / "docker-compose.prod.yml",
]


def _script_text(name: str) -> str:
    return (PROD_SCRIPTS_DIR / name).read_text(encoding="utf-8")


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _read_release_parity_package() -> str:
    return "\n".join(
        path.read_text(encoding="utf-8")
        for path in sorted(RELEASE_PARITY_AUDIT_DIR.glob("*.py"))
    )


if str(SECURITY_SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SECURITY_SCRIPTS_DIR))


def _write_clean_supply_chain_reports(reports_dir: Path) -> None:
    reports_dir.mkdir(parents=True, exist_ok=True)
    (reports_dir / "trivy-backend.json").write_text(
        '{"Results": []}\n', encoding="utf-8"
    )
    (reports_dir / "trivy-frontend.json").write_text(
        '{"Results": []}\n', encoding="utf-8"
    )
    (reports_dir / "grype-backend.json").write_text(
        '{"matches": []}\n', encoding="utf-8"
    )
    (reports_dir / "gitleaks-report.json").write_text("[]\n", encoding="utf-8")
    (reports_dir / "npm-audit-filtered.json").write_text(
        (
            "{\n"
            '  "raw_high_critical_packages": 0,\n'
            '  "accepted_high_critical_packages": 0,\n'
            '  "open_high_critical_packages": 0\n'
            "}\n"
        ),
        encoding="utf-8",
    )


@pytest.mark.parametrize(
    ("counter_name", "list_field"),
    [
        ("trivy_high_critical_count", "Results"),
        ("grype_high_critical_count", "matches"),
    ],
)
@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"scanner": "present-but-evidence-field-missing"},
        {"Results": {}, "matches": {}},
    ],
)
def test_prod_readiness_scanner_counts_fail_closed_on_malformed_evidence_shape(
    tmp_path: Path,
    counter_name: str,
    list_field: str,
    payload: dict[str, object],
) -> None:
    from prod_readiness_audit import scoring

    evidence_path = tmp_path / "scanner.json"
    evidence_path.write_text(json.dumps(payload), encoding="utf-8")

    counter = getattr(scoring, counter_name)
    assert counter(evidence_path) == 999

    evidence_path.write_text(json.dumps({list_field: []}), encoding="utf-8")
    assert counter(evidence_path) == 0


@pytest.mark.parametrize(
    ("counter_name", "payload"),
    [
        (
            "trivy_high_critical_count",
            {
                "Results": [
                    {},
                    {
                        "Vulnerabilities": [
                            {"Severity": "HIGH"},
                            {"Severity": "critical"},
                            {"Severity": "LOW"},
                        ]
                    },
                ]
            },
        ),
        (
            "grype_high_critical_count",
            {
                "matches": [
                    {"vulnerability": {"severity": "High"}},
                    {"vulnerability": {"severity": "CRITICAL"}},
                    {"vulnerability": {"severity": "Medium"}},
                ]
            },
        ),
    ],
)
def test_prod_readiness_scanner_counts_preserve_real_evidence_counts(
    tmp_path: Path, counter_name: str, payload: dict[str, object]
) -> None:
    from prod_readiness_audit import scoring

    evidence_path = tmp_path / "scanner.json"
    evidence_path.write_text(json.dumps(payload), encoding="utf-8")

    assert getattr(scoring, counter_name)(evidence_path) == 2


def _write_protocol_probe_results(
    state, *, unresolved: int = 0, security_defects: int = 0
) -> Path:
    probe_results = state.tmp_dir / "protocol" / "probe-results.json"
    probe_results.parent.mkdir(parents=True, exist_ok=True)
    probe_results.write_text(
        (
            "{\n"
            '  "summary": {\n'
            f'    "unresolved_contract_drift_count": {unresolved},\n'
            f'    "security_defect_count": {security_defects}\n'
            "  }\n"
            "}\n"
        ),
        encoding="utf-8",
    )
    (state.log_dir / "p2_security_contract_probe.log").write_text(
        f"wrote protocol probe output to {probe_results}\n",
        encoding="utf-8",
    )
    return probe_results


def _command_row(
    command_id: str, rc: int = 0, required: bool = True
) -> dict[str, object]:
    return {
        "id": command_id,
        "command": command_id,
        "cwd": str(REPO_ROOT),
        "start_utc": "2026-05-05T00:00:00+00:00",
        "end_utc": "2026-05-05T00:00:01+00:00",
        "duration_sec": 1.0,
        "rc": rc,
        "log": "",
        "required": required,
        "timeout_sec": 120,
    }


def _run_runtime_help(
    path: Path, env: dict[str, str] | None = None
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [str(path), "--help"],
        cwd=REPO_ROOT,
        check=False,
        capture_output=True,
        text=True,
        env=env,
    )


def test_preflight_exposes_allow_frontend_port_in_use_flag() -> None:
    text = _script_text("preflight.sh")
    assert "--allow-frontend-port-in-use" in text
    assert "allow_frontend_port_in_use=true" in text
    assert (
        'preflight_frontend_env "$FRONTEND_ENV" "$allow_frontend_port_in_use"' in text
    )


def test_preflight_contains_frontend_port_validation_messages() -> None:
    text = _script_text("lib/preflight.sh")
    assert "FRONTEND_HOST_PORT must be between 1 and 65535" in text
    assert "FRONTEND_CONTAINER_PORT must be numeric" in text
    assert "FRONTEND_CONTAINER_PORT must be between 1 and 65535" in text


def test_bootstrap_db_uses_module_execution_for_seed_scripts() -> None:
    text = _script_text("bootstrap_db.sh")
    assert "python -m scripts.seed_roles_permissions" in text
    assert "python -m scripts.seed_departments" in text
    assert "python -m scripts.bootstrap_sso_user" in text


def test_backend_dockerfile_keeps_builder_pip_out_of_runtime_images() -> None:
    text = _read(BACKEND_DOCKERFILE)

    assert "COPY --chown=riskhub:riskhub scripts ./scripts" not in text
    dockerfile_lines = text.splitlines()
    stage_bodies: dict[str, str] = {}
    stage_name: str | None = None
    for line in dockerfile_lines:
        stage_match = re.match(r"^FROM\s+\S+(?:\s+AS\s+(\S+))?$", line)
        if stage_match:
            stage_name = stage_match.group(1)
            if stage_name is not None:
                stage_bodies[stage_name] = ""
        elif stage_name is not None:
            stage_bodies[stage_name] += f"{line}\n"

    assert any(
        line.startswith("FROM python:3.13-alpine@sha256:")
        and line.endswith(" AS runtime")
        for line in dockerfile_lines
    )
    assert any(
        line.startswith("FROM python:3.13-alpine@sha256:")
        and line.endswith(" AS dbtasks")
        for line in dockerfile_lines
    )
    assert "COPY --from=builder-runtime" in text
    assert "COPY --from=builder-dbtasks" in text
    for builder_stage in ("builder-runtime", "builder-dbtasks"):
        assert (
            stage_bodies[builder_stage].count(
                "pip install --no-cache-dir --upgrade pip==26.2.1"
            )
            == 1
        )
    for runtime_stage in ("runtime", "dbtasks"):
        runtime_body = stage_bodies[runtime_stage]
        assert "pip install" not in runtime_body
        assert "python -m pip uninstall --yes pip" in runtime_body
        assert "rm -rf /usr/local/lib/python3.13/ensurepip" in runtime_body
    assert "pip==26.1.1" not in text
    assert "FROM runtime AS final" in text
    for script_name in EXPECTED_PROD_BOOTSTRAP_SCRIPTS:
        assert (
            f"COPY --chown=riskhub:riskhub scripts/{script_name} ./scripts/{script_name}"
            in text
        )

    assert text.count("libpq") == 1
    assert "\n    curl\n" not in text
    assert "urllib.request" in text
    assert "http://localhost:8000/api/v1/livez" in text
    assert "http://localhost:8000/api/v1/readyz" not in text


def test_backend_docker_runtime_owns_log_directory_after_source_mount() -> None:
    text = _read(BACKEND_DOCKERFILE)

    assert "docker-entrypoint.sh" in text
    assert "chown -R riskhub:riskhub /app/logs" in text
    assert 'ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]' in text


def test_dev_compose_bootstrap_uses_dbtasks_target_and_backend_inherits_image_healthcheck() -> (
    None
):
    text = _read(DEV_COMPOSE)

    assert "bootstrap:" in text
    assert "target: dbtasks" in text
    assert (
        'command: ["sh", "-lc", "python -m alembic upgrade head && python -m app.db.seed"]'
        in text
    )

    backend_block = text.split("  backend:\n", 1)[1].split("  frontend:\n", 1)[0]
    assert "healthcheck:" not in backend_block
    assert (
        'test: ["CMD", "curl", "-f", "http://localhost:8000/api/v1/health"]'
        not in backend_block
    )


def test_dev_compose_backend_services_share_managed_logs_volume() -> None:
    compose = yaml.safe_load(_read(DEV_COMPOSE))

    assert "riskhub_backend_logs" in compose["volumes"]
    for service_name in ("bootstrap", "backend", "scheduler"):
        assert "riskhub_backend_logs:/app/logs" in compose["services"][service_name][
            "volumes"
        ]
        assert "./backend/logs:/app/logs" not in compose["services"][service_name][
            "volumes"
        ]


def test_linux_bundle_builder_stages_only_bootstrap_scripts_and_prunes_dotfiles() -> (
    None
):
    text = _read(LINUX_BUNDLE_BUILDER)

    assert 'cp -R "${REPO_ROOT}/backend/scripts" "${BACKEND_STAGE}/scripts"' not in text
    assert (
        'cp -R "${REPO_ROOT}/backend/scripts" "${BACKEND_DB_STAGE}/scripts"' not in text
    )
    assert (
        'cp "${REPO_ROOT}/backend/requirements-runtime.txt" "${BACKEND_STAGE}/requirements-runtime.txt"'
        in text
    )
    assert "python3 -m pip download" in text
    assert '-r "${REPO_ROOT}/backend/requirements-db.txt"' in text
    for script_name in EXPECTED_PROD_BOOTSTRAP_SCRIPTS:
        assert (
            f'cp "${{REPO_ROOT}}/backend/scripts/{script_name}" "${{BACKEND_DB_STAGE}}/scripts/{script_name}"'
            in text
        )

    assert "../backend/requirements-runtime.txt" in text
    assert 'find "${STAGE_ROOT}" -name ".DS_Store" -delete' in text


def test_prod_install_and_release_gates_assert_minimal_backend_artifact_contract() -> (
    None
):
    makefile_text = _read(MAKEFILE)
    workflow_text = _read(RELEASE_WORKFLOW)

    assert "riskhub-backend-db" in makefile_text
    assert "riskhub-backend-db" in workflow_text
    assert "backend_db" in workflow_text
    assert "db-venv" in workflow_text

    for text in (makefile_text, workflow_text):
        assert "__init__.py" in text
        assert "bootstrap_sso_user.py" in text
        assert "revoke_refresh_sessions.py" in text
        assert "seed_departments.py" in text
        assert "seed_roles_permissions.py" in text
        assert "hidden = sorted" in text
        assert ".DS_Store" not in text or "rglob" in text or "find " in text


def test_install_frontend_applies_capability_hardening() -> None:
    text = _script_text("install_frontend.sh")
    assert "--security-opt no-new-privileges" in text
    assert "--cap-drop ALL" in text
    assert "--cap-add NET_BIND_SERVICE" in text


def test_frontend_dockerfile_uses_legacy_peer_resolution_for_container_builds() -> None:
    text = _read(FRONTEND_DOCKERFILE)
    assert "npm ci --include=dev --legacy-peer-deps" in text


def test_frontend_dockerfile_pins_runtime_base_digests() -> None:
    text = _read(FRONTEND_DOCKERFILE)

    assert "FROM node:24-alpine@sha256:" in text
    assert (
        text.count(
            "FROM nginx:alpine@sha256:"
            "db35bfc6b2951e7f8a72db5db120288c127ffaeeb4a6d4b95a26fead017d5913"
            " AS runtime"
        )
        == 1
    )
    assert (
        "54f2a904c251d5a34adf545a72d32515a15e08418dae0266e23be2e18c66fefa"
        not in text
    )
    assert "FROM node:24-alpine AS" not in text
    assert "FROM nginx:alpine AS" not in text
    assert "apk del --no-cache" in text
    assert "nginx-module-image-filter" in text
    assert "nginx-module-xslt" in text
    assert "\n    curl \\" in text


def test_install_redis_passes_password_file_override_for_custom_secret_dir() -> None:
    text = _script_text("install_redis.sh")
    assert "RISKHUB_REDIS_PASSWORD_FILE=${SECRET_DIR}/redis_password" in text


def test_removed_unsupported_deployment_artifacts_are_absent() -> None:
    for path in REMOVED_DEPLOYMENT_ARTIFACTS:
        assert (
            not path.exists()
        ), f"Unsupported deployment artifact should be removed: {path}"


@pytest.mark.parametrize(
    ("path", "default_var", "help_var"),
    [
        (
            BACKEND_RUNTIME_PROD,
            'DEFAULT_BACKEND_ENV="${RUNTIME_DIR}/backend.env"',
            "Default: ${DEFAULT_BACKEND_ENV}",
        ),
        (
            BACKEND_DB_RUNTIME_PROD,
            'DEFAULT_BACKEND_ENV="${RUNTIME_DIR}/backend.env"',
            "Default: ${DEFAULT_BACKEND_ENV}",
        ),
        (
            FRONTEND_RUNTIME_PROD,
            'DEFAULT_FRONTEND_ENV="${RUNTIME_DIR}/frontend.env"',
            "Default: ${DEFAULT_FRONTEND_ENV}",
        ),
    ],
)
def test_component_prod_wrappers_bind_default_env_paths_to_runtime_dir(
    path: Path,
    default_var: str,
    help_var: str,
) -> None:
    text = _read(path)

    assert default_var in text
    assert help_var in text
    assert "/etc/riskhub/backend.env" not in text
    assert "/etc/riskhub/frontend.env" not in text


@pytest.mark.parametrize(
    ("path", "expected_default"),
    [
        (BACKEND_RUNTIME_PROD, "Default: /etc/riskhub/runtime/backend.env"),
        (BACKEND_DB_RUNTIME_PROD, "Default: /etc/riskhub/runtime/backend.env"),
        (FRONTEND_RUNTIME_PROD, "Default: /etc/riskhub/runtime/frontend.env"),
    ],
)
def test_component_prod_wrappers_help_shows_runtime_dir_defaults(
    path: Path, expected_default: str
) -> None:
    result = _run_runtime_help(path, env=os.environ.copy())
    output = f"{result.stdout}\n{result.stderr}"

    assert result.returncode == 0, output
    assert expected_default in output


@pytest.mark.parametrize(
    ("path", "expected_suffix"),
    [
        (BACKEND_RUNTIME_PROD, "backend.env"),
        (BACKEND_DB_RUNTIME_PROD, "backend.env"),
        (FRONTEND_RUNTIME_PROD, "frontend.env"),
    ],
)
def test_component_prod_wrappers_help_honors_runtime_dir_override(
    path: Path, expected_suffix: str
) -> None:
    with tempfile.TemporaryDirectory(prefix="riskhub-runtime-help-") as td:
        env = os.environ.copy()
        env["RISKHUB_RUNTIME_DIR"] = td

        result = _run_runtime_help(path, env=env)
        output = f"{result.stdout}\n{result.stderr}"

        assert result.returncode == 0, output
        assert f"Default: {Path(td) / expected_suffix}" in output


def test_release_parity_audit_uses_deploy_cli_for_prod_runtime_path() -> None:
    runtime_text = _read(RELEASE_PARITY_AUDIT_RUNTIME)
    assert "deploy_cli_prod_docker" in runtime_text
    text = _read_release_parity_package()
    assert "./scripts/deploy.sh deploy --target docker" in text
    legacy_setup_mode_prod = "./scripts/" + "setup.sh --mode prod"
    forbidden = (
        legacy_setup_mode_prod,
        "setup_mode_prod",
        "path_setup_mode_prod_dryrun",
    )
    for token in forbidden:
        assert token not in text


def test_prod_readiness_audit_uses_deploy_cli_for_operator_lifecycle() -> None:
    shell_text = _read(
        REPO_ROOT / "scripts" / "security" / "run_prod_readiness_audit_local.sh"
    )
    phase_text = _read(
        REPO_ROOT / "scripts" / "security" / "prod_readiness_audit" / "phases.py"
    )
    package_text = shell_text + phase_text
    assert "prod_readiness_audit.cli" in shell_text

    required = (
        "./scripts/deploy.sh init --target docker",
        "./scripts/deploy.sh preflight --target docker",
        "./scripts/deploy.sh deploy --target docker",
        "./scripts/deploy.sh upgrade --target docker",
        "./scripts/deploy.sh rollback --target docker",
        "./scripts/deploy.sh smoke --target docker",
        "./scripts/deploy.sh status --target docker",
    )
    for token in required:
        assert token in package_text

    legacy_setup_mode_prod = "./scripts/" + "setup.sh --mode prod"
    forbidden = (
        "scripts/prod/setup.sh --",
        "scripts/prod/deploy.sh --",
        "scripts/prod/upgrade.sh --",
        "scripts/prod/stop.sh --",
        legacy_setup_mode_prod,
    )
    for token in forbidden:
        assert token not in package_text


def test_prod_readiness_phase_plan_prepares_config_and_images_before_preflight_and_deploy() -> (
    None
):
    from prod_readiness_audit.phases import build_prod_readiness_phases
    from prod_readiness_audit.run_state import build_run_state

    state = build_run_state(root_dir=REPO_ROOT, run_id="unit-test")
    phases = build_prod_readiness_phases(state)
    command_ids = [command.command_id for phase in phases for command in phase.commands]
    commands_by_id = {
        command.command_id: command.command
        for phase in phases
        for command in phase.commands
    }
    specs_by_id = {
        command.command_id: command for phase in phases for command in phase.commands
    }

    assert command_ids.index("p2_deploy_cli_init") < command_ids.index(
        "p2_populate_audit_config"
    )
    assert command_ids.index("p2_populate_audit_config") < command_ids.index(
        "p3_cli_preflight"
    )
    permission_command = commands_by_id["p2_normalize_audit_runtime_permissions"]
    assert command_ids.index("p2_verify_prod_install_scripts") < command_ids.index(
        "p2_normalize_audit_runtime_permissions"
    )
    assert command_ids.index("p2_populate_audit_config") < command_ids.index(
        "p2_normalize_audit_runtime_permissions"
    )
    assert command_ids.index(
        "p2_normalize_audit_runtime_permissions"
    ) < command_ids.index("p3_cli_preflight")
    assert "riskhub-backend-db:verify-prod-install-scripts" in permission_command
    assert "--entrypoint /bin/sh" in permission_command
    assert "--user 0:0" in permission_command
    assert "docker info --format '{{.OperatingSystem}}'" in permission_command
    assert "Docker Desktop" in permission_command
    assert "chgrp -R 10001" in permission_command
    assert "! -perm 0750" in permission_command
    assert "! -perm 0440" in permission_command
    assert "test -r" in permission_command
    assert specs_by_id["p2_normalize_audit_runtime_permissions"].required is True
    assert command_ids.index("p3_build_push_backend_deploy") < command_ids.index(
        "p3_cli_deploy"
    )
    assert command_ids.index("p3_build_push_backend_db_deploy") < command_ids.index(
        "p3_cli_deploy"
    )
    assert command_ids.index("p3_build_push_frontend_deploy") < command_ids.index(
        "p3_cli_deploy"
    )
    assert command_ids.index("p3_build_push_redis_deploy") < command_ids.index(
        "p3_cli_deploy"
    )
    assert command_ids.index("p3_build_push_backend_upgrade") < command_ids.index(
        "p3_cli_upgrade"
    )
    assert command_ids.index("p3_build_push_backend_db_upgrade") < command_ids.index(
        "p3_cli_upgrade"
    )
    assert command_ids.index("p3_build_push_frontend_upgrade") < command_ids.index(
        "p3_cli_upgrade"
    )
    assert command_ids.index("p3_build_push_redis_upgrade") < command_ids.index(
        "p3_cli_upgrade"
    )
    assert "127.0.0.1:" in commands_by_id["p3_resolve_deploy_image_digests"]
    assert "127.0.0.1:" in commands_by_id["p3_resolve_upgrade_image_digests"]


def test_prod_readiness_routes_prod_install_pytests_through_the_audit_python() -> None:
    from prod_readiness_audit.phases import build_prod_readiness_phases
    from prod_readiness_audit.run_state import build_run_state

    state = build_run_state(root_dir=REPO_ROOT, run_id="unit-test")
    commands_by_id = {
        command.command_id: command.command
        for phase in build_prod_readiness_phases(state)
        for command in phase.commands
    }
    verify_target = (
        _read(MAKEFILE)
        .split("verify-prod-install-scripts:", 1)[1]
        .split("\nverify-startup-scripts:", 1)[0]
    )

    assert commands_by_id["p2_verify_prod_install_scripts"].startswith(
        f"BACKEND_PYTHON={state.audit_python} "
    )
    assert "$(BACKEND_PYTHON) -m pytest" in verify_target
    assert "venv/bin/pytest" not in verify_target


def test_prod_readiness_backend_http_probes_use_the_runtime_python_stdlib() -> None:
    from prod_readiness_audit.phases import build_prod_readiness_phases
    from prod_readiness_audit.run_state import build_run_state

    state = build_run_state(root_dir=REPO_ROOT, run_id="unit-test")
    commands_by_id = {
        command.command_id: command.command
        for phase in build_prod_readiness_phases(state)
        for command in phase.commands
    }

    for command_id in ("p3_backend_docs_code", "p3_backend_openapi_code"):
        command = commands_by_id[command_id]
        assert command.startswith("docker exec riskhub-backend python -c ")
        assert "urllib.request" in command
        assert "curl" not in command
        assert "\n" not in command


def test_prod_readiness_security_probe_owns_bounded_local_runtime() -> None:
    from prod_readiness_audit.phases import build_prod_readiness_phases
    from prod_readiness_audit.run_state import build_run_state

    state = build_run_state(root_dir=REPO_ROOT, run_id="unit-test")
    command_ids = [
        command.command_id
        for phase in build_prod_readiness_phases(state)
        for command in phase.commands
    ]
    commands_by_id = {
        command.command_id: command.command
        for phase in build_prod_readiness_phases(state)
        for command in phase.commands
    }
    command = commands_by_id["p2_security_contract_probe"]

    assert command_ids.index("bootstrap_backend_audit_venv") < command_ids.index(
        "p2_security_contract_probe"
    )
    assert "trap cleanup EXIT INT TERM" in command
    assert "Base.metadata.create_all" in command
    assert "alembic_version" in command
    assert "-m app.db.seed" in command
    assert "-m uvicorn app.main:app" in command
    assert f"http://127.0.0.1:{state.security_probe_port}/api/v1/health" in command
    assert f"LOCAL_BASE_URL=http://127.0.0.1:{state.security_probe_port}" in command
    assert "INCLUDE_STAGING_SIM=false" in command
    assert "for attempt in {1..60}" in command
    assert "watchdog_pid" in command
    assert 'kill -0 "$parent_pid"' in command
    assert "|| true" not in command


def test_package_dependent_runtime_probes_execute_as_riskhub_user() -> None:
    smoke_script = _script_text("smoke_test.sh")
    verify_script = _script_text("verify_runtime.sh")

    assert (
        '| docker exec -i --user riskhub "$BACKEND_CONTAINER" python -' in smoke_script
    )
    assert (
        "docker exec -i --user riskhub \"$BACKEND_CONTAINER\" python - <<'PY'"
        in verify_script
    )


def test_docker_smoke_backend_http_probes_use_the_runtime_python_stdlib() -> None:
    smoke_script = _script_text("smoke_test.sh")

    assert "backend_http_code_python" in smoke_script
    assert "urllib.request" in smoke_script
    assert 'docker exec "$BACKEND_CONTAINER" curl' not in smoke_script


def test_prod_readiness_phase_plan_bootstraps_tracked_only_candidate_dependencies(
    tmp_path: Path,
) -> None:
    from packaging.requirements import Requirement
    from prod_readiness_audit.phases import build_prod_readiness_phases
    from prod_readiness_audit.run_state import build_run_state

    state = build_run_state(root_dir=REPO_ROOT, run_id="unit-test")
    state.artifact_root = tmp_path
    phases = build_prod_readiness_phases(state)
    command_ids = [command.command_id for phase in phases for command in phase.commands]
    commands_by_id = {
        command.command_id: command.command
        for phase in phases
        for command in phase.commands
    }

    backend_bootstrap = commands_by_id["bootstrap_backend_audit_venv"]
    frontend_bootstrap = commands_by_id["bootstrap_frontend_dependencies"]
    all_commands = "\n".join(commands_by_id.values())

    assert state.audit_venv == tmp_path / "tmp" / "audit-venv"
    assert '"$RISKHUB_AUDIT_PYTHON" -m venv' in backend_bootstrap
    assert "requirements-dev.txt" in backend_bootstrap
    assert (
        "-c backend/requirements-prod-readiness-audit-constraints.txt"
        in backend_bootstrap
    )
    assert "pip install --upgrade pip" not in backend_bootstrap
    assert "pip-audit==2.10.0" in backend_bootstrap
    assert "pip-audit>=" not in backend_bootstrap
    assert "npm ci --include=dev --legacy-peer-deps" in frontend_bootstrap
    assert command_ids.index("bootstrap_backend_audit_venv") < command_ids.index(
        "p2_prod_guard_pytests"
    )
    assert command_ids.index("bootstrap_frontend_dependencies") < command_ids.index(
        "p4_npm_audit_high"
    )
    assert "backend/venv" not in all_commands
    assert "./venv/bin" not in all_commands

    constraint_lines = [
        line.strip()
        for line in PROD_READINESS_AUDIT_CONSTRAINTS.read_text(
            encoding="utf-8"
        ).splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    constraint_requirements = [Requirement(line) for line in constraint_lines]
    constraint_names = {
        requirement.name.lower().replace("_", "-")
        for requirement in constraint_requirements
    }
    assert len(constraint_names) == len(constraint_requirements)
    assert all(
        len(requirement.specifier) == 1
        and next(iter(requirement.specifier)).operator == "=="
        and "*" not in next(iter(requirement.specifier)).version
        for requirement in constraint_requirements
    )

    requirements_to_visit = [REPO_ROOT / "backend" / "requirements-dev.txt"]
    direct_names = {"pip-audit"}
    while requirements_to_visit:
        requirement_path = requirements_to_visit.pop()
        for raw_line in requirement_path.read_text(encoding="utf-8").splitlines():
            line = raw_line.split("#", 1)[0].strip()
            if not line:
                continue
            if line.startswith("-r "):
                requirements_to_visit.append(requirement_path.parent / line[3:].strip())
                continue
            direct_names.add(Requirement(line).name.lower().replace("_", "-"))

    assert direct_names <= constraint_names


def test_prod_readiness_phase_plan_uses_one_verified_python313_interpreter(
    tmp_path: Path,
) -> None:
    from prod_readiness_audit.phases import build_prod_readiness_phases
    from prod_readiness_audit.run_state import build_run_state

    state = build_run_state(root_dir=REPO_ROOT, run_id="python313-plan")
    state.artifact_root = tmp_path
    state.python_executable = "/verified/bin/python3.13"
    commands_by_id = {
        command.command_id: command.command
        for phase in build_prod_readiness_phases(state)
        for command in phase.commands
    }

    assert '"$RISKHUB_AUDIT_PYTHON"' in commands_by_id["meta_python_version"]
    assert "sys.version_info[:2] == (3, 13)" in commands_by_id["meta_python_version"]
    assert commands_by_id["bootstrap_backend_audit_venv"].startswith(
        '"$RISKHUB_AUDIT_PYTHON" -m venv '
    )
    assert commands_by_id["p2_populate_audit_config"].startswith(
        '"$RISKHUB_AUDIT_PYTHON" -m prod_readiness_audit.audit_inputs '
    )


@pytest.mark.parametrize(
    ("python_fixture", "failure_code"),
    (
        ("missing", "python313_unavailable"),
        ("wrong-version", "python_version_unsupported"),
    ),
)
def test_prod_readiness_audit_records_python313_environment_blocker_before_venv(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    python_fixture: str,
    failure_code: str,
) -> None:
    from prod_readiness_audit import cli as prod_cli
    from prod_readiness_audit.run_state import build_run_state

    python_path = tmp_path / python_fixture
    if python_fixture == "wrong-version":
        python_path.write_text(
            "#!/bin/sh\n"
            'if [ "${1:-}" = "--version" ]; then\n'
            "  echo 'Python 3.14.0'\n"
            "fi\n"
            "exit 1\n",
            encoding="utf-8",
        )
        python_path.chmod(0o755)

    state = build_run_state(root_dir=REPO_ROOT, run_id=f"python313-{python_fixture}")
    state.artifact_root = tmp_path / "artifact"
    monkeypatch.setattr(prod_cli, "build_run_state", lambda **_kwargs: state)

    assert (
        prod_cli.run_prod_readiness_audit(
            run_id=state.run_id, python_bin=str(python_path)
        )
        == 1
    )

    summary = json.loads(
        (state.artifact_root / "SUMMARY.json").read_text(encoding="utf-8")
    )
    assert summary["failure_classification"] == "environment_contamination"
    assert summary["failure_code"] == failure_code
    assert summary["failure_command_id"] == "meta_python_version"
    assert not state.audit_venv.exists()


def test_prod_readiness_phase_plan_resolves_registry_tags_before_deploy_and_upgrade(
    tmp_path: Path,
) -> None:
    from prod_readiness_audit.phases import build_prod_readiness_phases
    from prod_readiness_audit.run_state import build_run_state

    state = build_run_state(root_dir=REPO_ROOT, run_id="unit-test")
    state.artifact_root = tmp_path / "artifacts"
    state.ensure_directories()
    phases = build_prod_readiness_phases(state)
    command_ids = [command.command_id for phase in phases for command in phase.commands]
    commands_by_id = {
        command.command_id: command.command
        for phase in phases
        for command in phase.commands
    }

    deploy_resolver = commands_by_id["p3_resolve_deploy_image_digests"]
    upgrade_resolver = commands_by_id["p3_resolve_upgrade_image_digests"]
    deploy = commands_by_id["p3_cli_deploy"]
    upgrade = commands_by_id["p3_cli_upgrade"]

    assert "RepoDigests" in deploy_resolver
    assert "RepoDigests" in upgrade_resolver
    assert "@sha256:" in deploy_resolver
    assert "@sha256:" in upgrade_resolver
    assert command_ids.index("p3_build_push_redis_deploy") < command_ids.index(
        "p3_resolve_deploy_image_digests"
    )
    assert command_ids.index("p3_resolve_deploy_image_digests") < command_ids.index(
        "p3_cli_deploy"
    )
    assert command_ids.index("p3_build_push_redis_upgrade") < command_ids.index(
        "p3_resolve_upgrade_image_digests"
    )
    assert command_ids.index("p3_resolve_upgrade_image_digests") < command_ids.index(
        "p3_cli_upgrade"
    )
    for command in (deploy, upgrade):
        assert "$(cat " in command
        assert "--backend-image" in command
        assert "--backend-db-image" in command
        assert "--frontend-image" in command
        assert "--redis-image" in command

    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    fake_docker = fake_bin / "docker"
    fake_docker.write_text(
        "#!/bin/sh\n"
        'if [ "$1" = pull ]; then exit 0; fi\n'
        'if [ "$1" = image ] && [ "$2" = inspect ]; then\n'
        '  tag="$5"\n'
        '  repo="${tag%:*}"\n'
        "  printf '%s@sha256:%064d\\n' \"$repo\" 0\n"
        "  exit 0\n"
        "fi\n"
        "exit 2\n",
        encoding="utf-8",
    )
    fake_docker.chmod(0o755)
    env = os.environ.copy()
    env["PATH"] = f"{fake_bin}:{env['PATH']}"

    resolved = subprocess.run(
        ["bash", "-c", deploy_resolver],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
    )

    assert resolved.returncode == 0, f"{resolved.stdout}\n{resolved.stderr}"
    resolved_refs = sorted(state.tmp_dir.glob("*-image-deploy.ref"))
    assert len(resolved_refs) == 4
    for ref_path in resolved_refs:
        assert (
            ref_path.read_text(encoding="utf-8").strip().endswith("@sha256:" + "0" * 64)
        )

    fake_docker.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    unresolved = subprocess.run(
        ["bash", "-c", upgrade_resolver],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
    )

    assert unresolved.returncode != 0


def test_prod_readiness_detached_tree_gitleaks_scan_uses_no_git_mode_and_fails_closed() -> (
    None
):
    from prod_readiness_audit.phases import build_prod_readiness_phases
    from prod_readiness_audit.run_state import build_run_state

    state = build_run_state(root_dir=REPO_ROOT, run_id="unit-test")
    supply_chain = next(
        phase
        for phase in build_prod_readiness_phases(state)
        if phase.name == "supply_chain"
    )
    scan = next(
        command
        for command in supply_chain.commands
        if command.command_id == "p4_gitleaks_scan"
    )

    assert "--source /repo --no-git" in scan.command
    assert "--exit-code 1" in scan.command
    assert scan.required is True


def test_grype_policy_has_no_runtime_acceptances() -> None:
    policy = yaml.safe_load(GRYPE_IGNORE.read_text(encoding="utf-8"))
    assert policy == {"ignore": []}


def test_prod_readiness_phase_plan_restores_negative_probes_and_runtime_verification() -> (
    None
):
    from prod_readiness_audit.phases import build_prod_readiness_phases
    from prod_readiness_audit.run_state import build_run_state

    state = build_run_state(root_dir=REPO_ROOT, run_id="unit-test")
    phases = build_prod_readiness_phases(state)
    command_ids = [command.command_id for phase in phases for command in phase.commands]
    commands_by_id = {
        command.command_id: command for phase in phases for command in phase.commands
    }

    for command_id in (
        "p2_unsupported_prod_artifacts_absent",
        "p2_preflight_invalid_host_range",
        "p2_preflight_invalid_container_port",
    ):
        assert command_id in command_ids
        assert commands_by_id[command_id].required is False
        assert command_ids.index("p2_populate_audit_config") < command_ids.index(
            command_id
        )

    assert command_ids.index("p3_status_after_deploy") < command_ids.index(
        "p3_verify_runtime"
    )
    assert command_ids.index("p3_verify_runtime") < command_ids.index(
        "p3_cli_smoke_after_deploy"
    )


def test_prod_readiness_audit_restores_full_supply_chain_gates() -> None:
    from prod_readiness_audit.phases import build_prod_readiness_phases
    from prod_readiness_audit.run_state import build_run_state

    state = build_run_state(root_dir=REPO_ROOT, run_id="unit-test")
    supply_chain = next(
        phase
        for phase in build_prod_readiness_phases(state)
        if phase.name == "supply_chain"
    )
    command_ids = {command.command_id for command in supply_chain.commands}
    command_text = "\n".join(command.command for command in supply_chain.commands)

    assert {
        "p4_bandit_high_gate",
        "p4_pip_audit",
        "p4_npm_audit_high",
        "p4_trivy_backend",
        "p4_trivy_frontend",
        "p4_syft_backend",
        "p4_grype_backend",
        "p4_gitleaks_scan",
    }.issubset(command_ids)
    assert ":latest" not in command_text


def test_prod_readiness_audit_input_writer_replaces_init_placeholders() -> None:
    from prod_readiness_audit.audit_inputs import write_audit_inputs
    from prod_readiness_audit.run_state import build_run_state

    with tempfile.TemporaryDirectory(prefix="riskhub-prod-readiness-inputs-") as td:
        state = build_run_state(root_dir=REPO_ROOT, run_id="unit-test")
        state.artifact_root = Path(td)
        state.ensure_directories()

        write_audit_inputs(state)

        assert "CHANGE_ME" not in state.config_path.read_text(encoding="utf-8")
        assert "CHANGE_ME" not in (state.secret_dir / "database_url").read_text(
            encoding="utf-8"
        )
        assert (state.secret_dir / "secret_key").read_text(encoding="utf-8").strip()
        assert (state.secret_dir / "redis_password").read_text(encoding="utf-8").strip()
        assert (state.runtime_dir / "redis_url").read_text(encoding="utf-8").strip()
        assert (state.tmp_dir / "backend_valid.env").exists()
        backend_values = dict(
            line.split("=", 1)
            for line in (state.tmp_dir / "backend_valid.env")
            .read_text(encoding="utf-8")
            .splitlines()
        )
        assert backend_values["REFRESH_TOKEN_MIGRATION_GRACE"] == "false"
        assert backend_values["ACCESS_TOKEN_EXPIRE_MINUTES"] == "30"
        assert backend_values["PLATFORM_ADMIN_ACCESS_TOKEN_EXPIRE_MINUTES"] == "15"
        assert backend_values["DIRECTORY_PROVIDER"] == "graph"
        assert backend_values["ENTRA_JIT_PROVISIONING_ENABLED"] == "false"
        assert backend_values["AUTH_SSO_ALLOW_EMAIL_LINK"] == "false"
        audit_config = dict(
            line.split("=", 1)
            for line in state.config_path.read_text(encoding="utf-8").splitlines()
        )
        assert audit_config["BOOTSTRAP_ADMIN_EXTERNAL_ID"] == (
            "11111111-2222-4333-8444-555555555555"
        )
        assert audit_config["BOOTSTRAP_CRO_EXTERNAL_ID"] == (
            "66666666-7777-4888-8999-aaaaaaaaaaaa"
        )
        assert (
            audit_config["BOOTSTRAP_ADMIN_EXTERNAL_ID"]
            != audit_config["BOOTSTRAP_CRO_EXTERNAL_ID"]
        )
        assert "FRONTEND_HOST_PORT=70000" in (
            state.tmp_dir / "frontend_invalid_host.env"
        ).read_text(encoding="utf-8")
        assert "FRONTEND_CONTAINER_PORT=abc" in (
            state.tmp_dir / "frontend_invalid_container.env"
        ).read_text(encoding="utf-8")


@pytest.mark.parametrize(
    ("command_id", "expected_diagnostic"),
    [
        (
            "p2_preflight_invalid_host_range",
            "FRONTEND_HOST_PORT must be between 1 and 65535",
        ),
        (
            "p2_preflight_invalid_container_port",
            "FRONTEND_CONTAINER_PORT must be numeric",
        ),
    ],
)
def test_prod_readiness_generated_negative_probe_reaches_frontend_validation(
    command_id: str, expected_diagnostic: str
) -> None:
    from prod_readiness_audit.audit_inputs import write_audit_inputs
    from prod_readiness_audit.phases import build_prod_readiness_phases
    from prod_readiness_audit.run_state import build_run_state

    with tempfile.TemporaryDirectory(
        prefix="riskhub-prod-readiness-generated-negative-probe-"
    ) as td:
        state = build_run_state(root_dir=REPO_ROOT, run_id="unit-test")
        state.artifact_root = Path(td)
        state.ensure_directories()
        write_audit_inputs(state)
        command = next(
            command
            for phase in build_prod_readiness_phases(state)
            for command in phase.commands
            if command.command_id == command_id
        )

        fake_bin = state.tmp_dir / "fake-bin"
        fake_bin.mkdir()
        fake_docker = fake_bin / "docker"
        fake_docker.write_text(
            "#!/bin/sh\n"
            'if [ "$#" -eq 1 ] && [ "$1" = ps ]; then exit 0; fi\n'
            "printf 'unexpected docker invocation: %s\\n' \"$*\" >&2\n"
            "exit 97\n",
            encoding="utf-8",
        )
        fake_docker.chmod(0o755)
        controlled_path = f"{fake_bin}:{os.environ['PATH']}"

        completed = subprocess.run(
            [
                "bash",
                "-lc",
                f"PATH={shlex.quote(controlled_path)} {command.command}",
            ],
            cwd=REPO_ROOT,
            env={
                **os.environ,
                "RISKHUB_AUDIT_PYTHON": state.python_executable,
            },
            capture_output=True,
            text=True,
            check=False,
        )

    assert completed.returncode != 0
    assert "unexpected docker invocation:" not in completed.stderr
    assert expected_diagnostic in completed.stderr


def _run_production_backend_preflight(
    backend_env: Path, *, secret_dir: Path, runtime_dir: Path
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            "bash",
            "-c",
            'source "$1"; source "$2"; preflight_backend_env "$3"',
            "bash",
            str(PROD_SCRIPTS_DIR / "lib" / "common.sh"),
            str(PROD_PREFLIGHT_LIB),
            str(backend_env),
        ],
        cwd=REPO_ROOT,
        env={
            **os.environ,
            "RISKHUB_DEFAULT_SECRET_DIR": str(secret_dir),
            "RISKHUB_RUNTIME_DIR": str(runtime_dir),
        },
        capture_output=True,
        text=True,
        check=False,
    )


@pytest.mark.parametrize(
    "configured_value",
    ["true", None],
    ids=["enabled", "missing"],
)
def test_production_preflight_rejects_non_strict_refresh_token_migration_grace(
    tmp_path: Path, configured_value: str | None
) -> None:
    from prod_readiness_audit.audit_inputs import write_audit_inputs
    from prod_readiness_audit.run_state import build_run_state

    state = build_run_state(root_dir=REPO_ROOT, run_id="unit-test")
    state.artifact_root = tmp_path
    state.ensure_directories()
    write_audit_inputs(state)
    backend_env = state.tmp_dir / "backend_valid.env"
    lines = backend_env.read_text(encoding="utf-8").splitlines()
    lines = [
        line
        for line in lines
        if not line.startswith("REFRESH_TOKEN_MIGRATION_GRACE=")
    ]
    if configured_value is not None:
        lines.append(f"REFRESH_TOKEN_MIGRATION_GRACE={configured_value}")
    backend_env.write_text("\n".join(lines) + "\n", encoding="utf-8")

    completed = _run_production_backend_preflight(
        backend_env,
        secret_dir=state.secret_dir,
        runtime_dir=state.runtime_dir,
    )

    assert completed.returncode != 0
    assert (
        f"Expected REFRESH_TOKEN_MIGRATION_GRACE=false in {backend_env}"
        in completed.stderr
    )


def test_production_preflight_accepts_disabled_refresh_token_migration_grace(
    tmp_path: Path,
) -> None:
    from prod_readiness_audit.audit_inputs import write_audit_inputs
    from prod_readiness_audit.run_state import build_run_state

    state = build_run_state(root_dir=REPO_ROOT, run_id="unit-test")
    state.artifact_root = tmp_path
    state.ensure_directories()
    write_audit_inputs(state)
    backend_env = state.tmp_dir / "backend_valid.env"

    completed = _run_production_backend_preflight(
        backend_env,
        secret_dir=state.secret_dir,
        runtime_dir=state.runtime_dir,
    )

    assert completed.returncode == 0, completed.stderr


@pytest.mark.parametrize(
    ("key", "required_value", "drift_value"),
    [
        ("ACCESS_TOKEN_EXPIRE_MINUTES", "30", "31"),
        ("ACCESS_TOKEN_EXPIRE_MINUTES", "30", None),
        ("PLATFORM_ADMIN_ACCESS_TOKEN_EXPIRE_MINUTES", "15", "16"),
        ("PLATFORM_ADMIN_ACCESS_TOKEN_EXPIRE_MINUTES", "15", None),
    ],
)
def test_production_preflight_rejects_access_token_lifetime_drift(
    tmp_path: Path,
    key: str,
    required_value: str,
    drift_value: str | None,
) -> None:
    from prod_readiness_audit.audit_inputs import write_audit_inputs
    from prod_readiness_audit.run_state import build_run_state

    state = build_run_state(root_dir=REPO_ROOT, run_id="unit-test")
    state.artifact_root = tmp_path
    state.ensure_directories()
    write_audit_inputs(state)
    backend_env = state.tmp_dir / "backend_valid.env"
    lines = [
        line
        for line in backend_env.read_text(encoding="utf-8").splitlines()
        if not line.startswith(f"{key}=")
    ]
    if drift_value is not None:
        lines.append(f"{key}={drift_value}")
    backend_env.write_text("\n".join(lines) + "\n", encoding="utf-8")

    completed = _run_production_backend_preflight(
        backend_env,
        secret_dir=state.secret_dir,
        runtime_dir=state.runtime_dir,
    )

    assert completed.returncode != 0
    assert f"Expected {key}={required_value} in {backend_env}" in completed.stderr


def test_prod_readiness_scoring_rejects_unrelated_negative_probe_failures() -> None:
    from prod_readiness_audit.run_state import build_run_state
    from prod_readiness_audit.scoring import evaluate_mandatory_controls

    with tempfile.TemporaryDirectory(
        prefix="riskhub-prod-readiness-negative-probes-"
    ) as td:
        state = build_run_state(root_dir=REPO_ROOT, run_id="unit-test")
        state.artifact_root = Path(td)
        state.ensure_directories()
        (state.log_dir / "p2_preflight_invalid_host_range.log").write_text(
            "Expected DIRECTORY_PROVIDER=graph in backend_valid.env\n",
            encoding="utf-8",
        )
        (state.log_dir / "p2_preflight_invalid_container_port.log").write_text(
            "Expected DIRECTORY_PROVIDER=graph in backend_valid.env\n",
            encoding="utf-8",
        )
        state.command_results = [
            _command_row("p2_preflight_invalid_host_range", rc=1, required=False),
            _command_row(
                "p2_preflight_invalid_container_port", rc=1, required=False
            ),
        ]

        findings = evaluate_mandatory_controls(state)

    assert "MC-06" in {str(finding["id"]) for finding in findings}


def test_prod_readiness_scoring_fails_semantic_mandatory_control_regressions() -> None:
    from prod_readiness_audit.run_state import build_run_state
    from prod_readiness_audit.scoring import score_command_results

    with tempfile.TemporaryDirectory(
        prefix="riskhub-prod-readiness-scoring-fail-"
    ) as td:
        state = build_run_state(root_dir=REPO_ROOT, run_id="unit-test")
        state.artifact_root = Path(td)
        state.ensure_directories()
        _write_clean_supply_chain_reports(state.reports_dir)
        _write_protocol_probe_results(state)
        (state.log_dir / "p3_frontend_uid.log").write_text("0\n", encoding="utf-8")
        (state.log_dir / "p3_backend_docs_code.log").write_text(
            "200\n", encoding="utf-8"
        )
        (state.log_dir / "p3_backend_openapi_code.log").write_text(
            "200\n", encoding="utf-8"
        )
        state.command_results = [
            _command_row("p2_security_contract_probe"),
            _command_row("p2_preflight_invalid_host_range", rc=0, required=False),
            _command_row("p2_preflight_invalid_container_port", rc=0, required=False),
            _command_row("p2_unsupported_prod_artifacts_absent", rc=0, required=False),
            _command_row("p3_cli_preflight"),
            _command_row("p3_cli_deploy"),
            _command_row("p3_status_after_deploy"),
            _command_row("p3_cli_smoke_after_deploy"),
            _command_row("p3_cli_upgrade"),
            _command_row("p3_cli_rollback"),
            _command_row("p3_cli_smoke_after_rollback"),
            _command_row("p3_backend_docs_code"),
            _command_row("p3_backend_openapi_code"),
            _command_row("p3_frontend_uid"),
        ]

        findings, _scorecard = score_command_results(state)

    finding_ids = {str(finding["id"]) for finding in findings}
    assert {"MC-06", "MC-08", "MC-09", "MC-10"}.issubset(finding_ids)


def test_prod_readiness_scoring_fails_protocol_probe_summary_regressions() -> None:
    from prod_readiness_audit.run_state import build_run_state
    from prod_readiness_audit.scoring import score_command_results

    with tempfile.TemporaryDirectory(
        prefix="riskhub-prod-readiness-scoring-protocol-"
    ) as td:
        state = build_run_state(root_dir=REPO_ROOT, run_id="unit-test")
        state.artifact_root = Path(td)
        state.ensure_directories()
        _write_clean_supply_chain_reports(state.reports_dir)
        _write_protocol_probe_results(state, unresolved=2, security_defects=1)
        (state.log_dir / "p3_frontend_uid.log").write_text("101\n", encoding="utf-8")
        (state.log_dir / "p3_backend_docs_code.log").write_text(
            "404\n", encoding="utf-8"
        )
        (state.log_dir / "p3_backend_openapi_code.log").write_text(
            "404\n", encoding="utf-8"
        )
        (state.log_dir / "p2_preflight_invalid_host_range.log").write_text(
            "FRONTEND_HOST_PORT must be between 1 and 65535\n",
            encoding="utf-8",
        )
        (
            state.log_dir / "p2_preflight_invalid_container_port.log"
        ).write_text(
            "FRONTEND_CONTAINER_PORT must be numeric\n",
            encoding="utf-8",
        )
        state.command_results = [
            _command_row("p2_security_contract_probe"),
            _command_row("p2_preflight_invalid_host_range", rc=1, required=False),
            _command_row("p2_preflight_invalid_container_port", rc=1, required=False),
            _command_row("p2_unsupported_prod_artifacts_absent", rc=0, required=False),
            _command_row("p3_cli_preflight"),
            _command_row("p3_cli_deploy"),
            _command_row("p3_status_after_deploy"),
            _command_row("p3_verify_runtime"),
            _command_row("p3_cli_smoke_after_deploy"),
            _command_row("p3_cli_upgrade"),
            _command_row("p3_cli_rollback"),
            _command_row("p3_cli_smoke_after_rollback"),
            _command_row("p3_backend_docs_code"),
            _command_row("p3_backend_openapi_code"),
            _command_row("p3_frontend_uid"),
        ]

        findings, _scorecard = score_command_results(state)

    matching = [finding for finding in findings if finding["id"] == "MC-11"]
    assert matching
    assert matching[0]["details"] == {
        "unresolved_contract_drift_count": 2,
        "security_defect_count": 1,
    }


def test_prod_readiness_scoring_passes_semantic_mandatory_controls() -> None:
    from prod_readiness_audit.run_state import build_run_state
    from prod_readiness_audit.scoring import score_command_results

    with tempfile.TemporaryDirectory(
        prefix="riskhub-prod-readiness-scoring-pass-"
    ) as td:
        state = build_run_state(root_dir=REPO_ROOT, run_id="unit-test")
        state.artifact_root = Path(td)
        state.ensure_directories()
        _write_clean_supply_chain_reports(state.reports_dir)
        _write_protocol_probe_results(state)
        (state.log_dir / "p3_frontend_uid.log").write_text("101\n", encoding="utf-8")
        (state.log_dir / "p3_backend_docs_code.log").write_text(
            "404\n", encoding="utf-8"
        )
        (state.log_dir / "p3_backend_openapi_code.log").write_text(
            "404\n", encoding="utf-8"
        )
        (state.log_dir / "p2_preflight_invalid_host_range.log").write_text(
            "FRONTEND_HOST_PORT must be between 1 and 65535\n",
            encoding="utf-8",
        )
        (
            state.log_dir / "p2_preflight_invalid_container_port.log"
        ).write_text(
            "FRONTEND_CONTAINER_PORT must be numeric\n",
            encoding="utf-8",
        )
        state.command_results = [
            _command_row("p2_security_contract_probe"),
            _command_row("p2_preflight_invalid_host_range", rc=1, required=False),
            _command_row("p2_preflight_invalid_container_port", rc=1, required=False),
            _command_row("p2_unsupported_prod_artifacts_absent", rc=0, required=False),
            _command_row("p3_cli_preflight"),
            _command_row("p3_cli_deploy"),
            _command_row("p3_status_after_deploy"),
            _command_row("p3_verify_runtime"),
            _command_row("p3_cli_smoke_after_deploy"),
            _command_row("p3_cli_upgrade"),
            _command_row("p3_cli_rollback"),
            _command_row("p3_cli_smoke_after_rollback"),
            _command_row("p3_backend_docs_code"),
            _command_row("p3_backend_openapi_code"),
            _command_row("p3_frontend_uid"),
        ]

        findings, _scorecard = score_command_results(state)

    assert findings == []


def test_prod_readiness_timeout_records_matrix_row_and_continues(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from prod_readiness_audit.commands import ProdReadinessCommand, run_command
    from prod_readiness_audit.run_state import build_run_state

    def raise_timeout(
        *_args: object, **_kwargs: object
    ) -> subprocess.CompletedProcess[str]:
        raise subprocess.TimeoutExpired(
            cmd="sleep 10",
            timeout=1,
            output="partial stdout",
            stderr="partial stderr",
        )

    monkeypatch.setattr(subprocess, "run", raise_timeout)
    with tempfile.TemporaryDirectory(prefix="riskhub-prod-readiness-timeout-") as td:
        state = build_run_state(root_dir=REPO_ROOT, run_id="unit-test")
        state.artifact_root = Path(td)
        state.ensure_directories()

        row = run_command(
            state,
            ProdReadinessCommand(
                "non_required_timeout", "sleep 10", required=False, timeout_sec=1
            ),
        )

        assert row["rc"] == 124
        assert row["timed_out"] is True
        result_path = Path(str(row["result"]))
        assert result_path.is_relative_to(state.artifact_root)
        assert json.loads(result_path.read_text(encoding="utf-8")) == {
            "id": "non_required_timeout",
            "command": "sleep 10",
            "rc": 124,
            "timed_out": True,
        }
        assert state.required_failures == 0
        assert "partial stdout" in (
            state.log_dir / "non_required_timeout.log"
        ).read_text(encoding="utf-8")
        assert '"timed_out": true' in state.matrix_ndjson.read_text(encoding="utf-8")

        run_command(
            state, ProdReadinessCommand("required_timeout", "sleep 10", timeout_sec=1)
        )

        assert state.required_failures == 1


def test_prod_readiness_command_preserves_caller_selected_node(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from prod_readiness_audit.commands import ProdReadinessCommand, run_command
    from prod_readiness_audit.run_state import build_run_state

    home_dir = tmp_path / "home"
    node24_dir = tmp_path / "node24"
    node26_dir = tmp_path / "node26"
    home_dir.mkdir()
    node24_dir.mkdir()
    node26_dir.mkdir()

    for directory, version in ((node24_dir, "v24.0.0"), (node26_dir, "v26.0.0")):
        node = directory / "node"
        node.write_text(
            f"#!/usr/bin/env bash\nprintf '%s\\n' '{version}'\n",
            encoding="utf-8",
        )
        node.chmod(0o755)

    (home_dir / ".bash_profile").write_text(
        f'export PATH="{node26_dir}:$PATH"\n', encoding="utf-8"
    )
    monkeypatch.setenv("HOME", str(home_dir))
    monkeypatch.setenv("PATH", f"{node24_dir}:{os.environ['PATH']}")

    state = build_run_state(root_dir=REPO_ROOT, run_id="node-path-test")
    state.artifact_root = tmp_path / "artifacts"
    state.ensure_directories()

    row = run_command(
        state,
        ProdReadinessCommand("node_version", "node --version"),
    )

    assert row["rc"] == 0
    assert (
        state.log_dir / "node_version.log"
    ).read_text(encoding="utf-8") == "$ node --version\n\nv24.0.0\n"


def test_prod_readiness_audit_preserves_run_status_and_exit_finalization() -> None:
    shell_text = _read(
        REPO_ROOT / "scripts" / "security" / "run_prod_readiness_audit_local.sh"
    )
    run_state_text = _read(
        REPO_ROOT / "scripts" / "security" / "prod_readiness_audit" / "run_state.py"
    )
    artifacts_text = _read(
        REPO_ROOT / "scripts" / "security" / "prod_readiness_audit" / "artifacts.py"
    )
    cli_text = _read(
        REPO_ROOT / "scripts" / "security" / "prod_readiness_audit" / "cli.py"
    )

    assert "python3 -m prod_readiness_audit.cli" in shell_text
    assert 'return self.reports_dir / "run_status.json"' in run_state_text
    assert 'return self.reports_dir / "report.md"' in run_state_text
    assert "def write_json(" in artifacts_text
    assert "def write_incomplete_artifacts(" in artifacts_text
    assert "except BaseException" in cli_text
    assert "state.planned_command_ids = [" in cli_text
    assert "write_final_artifacts(state)" in cli_text


def test_prod_readiness_run_status_records_the_complete_planned_command_inventory(
    tmp_path: Path,
) -> None:
    from prod_readiness_audit.artifacts import build_run_status
    from prod_readiness_audit.run_state import build_run_state

    state = build_run_state(root_dir=REPO_ROOT, run_id="planned-inventory")
    state.artifact_root = tmp_path / "artifact"
    state.planned_command_ids = ["first", "second"]
    state.command_results = [
        {"id": "first", "required": True, "rc": 0},
        {"id": "second", "required": True, "rc": 0},
    ]
    state.planned_run_complete = True

    status = build_run_status(state, status="complete", exit_code=0)

    assert status["planned_command_ids"] == ["first", "second"]
    assert status["planned_command_count"] == 2
    assert status["completed_command_count"] == 2
    assert status["planned_run_complete"] is True
    assert status["plan_inputs"] == {
        "root_dir": str(REPO_ROOT),
        "artifact_root": str(tmp_path / "artifact"),
        "report_path": str(state.report_path),
        "report_date": state.report_date,
        "postgres_port": state.postgres_port,
        "frontend_host_port": state.frontend_host_port,
        "registry_port": state.registry_port,
        "security_probe_port": state.security_probe_port,
    }


def test_redis_entrypoint_allows_passthrough_commands_for_image_contract_checks() -> (
    None
):
    text = _read(REPO_ROOT / "docker" / "redis" / "entrypoint.sh")

    assert 'if [ "$#" -gt 0 ] && [ "$1" != "redis-server" ]; then' in text
    assert 'exec "$@"' in text


def test_active_docs_do_not_reference_removed_or_unsupported_deployment_paths() -> None:
    forbidden_tokens = (
        "scripts/prod/setup.sh",
        "scripts/prod/deploy.sh",
        "scripts/prod/upgrade.sh",
        "scripts/prod/stop.sh",
        "component-runtime-entrypoints.md",
        "docker-compose.prod.yml",
        "docs/deployment/docker-compose-prod.md",
        "docs/deployment/kubernetes.md",
        "docs/deployment/installation-manual.md",
        "docs/deployment/external-postgres-install-scripts.md",
        "Docker/K8s",
        "Docker + K8s",
    )
    for path in ACTIVE_DOCS:
        text = _read(path)
        for token in forbidden_tokens:
            assert (
                token not in text
            ), f"Unsupported deployment reference in {path}: {token}"


def test_bootstrap_external_id_operator_contract_is_documented() -> None:
    external_id_keys = (
        "BOOTSTRAP_ADMIN_EXTERNAL_ID",
        "BOOTSTRAP_CRO_EXTERNAL_ID",
    )
    example_paths = (
        REPO_ROOT / "scripts" / "deploy" / "templates" / "riskhub.env.example",
        REPO_ROOT / "scripts" / "prod" / "config" / "backend.env.example",
    )
    for path in example_paths:
        text = _read(path)
        for key in external_id_keys:
            assert re.search(rf"(?m)^#?\s*{key}=\s*$", text), (
                f"{path} must document {key} as blank or commented"
            )

    bootstrap_help = subprocess.run(
        ["bash", str(PROD_SCRIPTS_DIR / "bootstrap_db.sh"), "--help"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.lower()
    assert "omitted external ids use exact email/upn graph lookup" in bootstrap_help
    assert "supplied external ids skip graph lookup and are trusted operator assertions" in bootstrap_help

    backend_example = _read(
        REPO_ROOT / "scripts" / "prod" / "config" / "backend.env.example"
    ).lower()
    assert "omitted external ids use exact email/upn graph lookup" in backend_example
    assert "supplied external ids skip graph lookup and are trusted operator assertions" in backend_example

    reference_text = _read(REPO_ROOT / "docs" / "deployment" / "reference.md")
    for key in external_id_keys:
        assert f"- `{key}`" in reference_text

    production_text = _read(
        REPO_ROOT / "docs" / "deployment" / "production.md"
    ).lower()
    for phrase in (
        "exact email/upn graph lookup",
        "fails closed",
        "graph lookup is skipped",
        "trusted operator assertion",
        "configured entra tenant",
        "independently verify",
    ):
        assert phrase in production_text

    checklist_text = _read(
        REPO_ROOT / "docs" / "deployment" / "security-checklist.md"
    ).lower()
    assert "bootstrap admin/cro external ids are distinct" in checklist_text
    assert "correspondence to the configured email/upn is verified" in checklist_text
