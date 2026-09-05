from __future__ import annotations

import sys
from datetime import date
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
SECURITY_SCRIPTS_DIR = REPO_ROOT / "scripts" / "security"
GRYPE_IGNORE = REPO_ROOT / "backend" / "security" / "grype-ignore.yaml"
if str(SECURITY_SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SECURITY_SCRIPTS_DIR))


def _policy(*, expires_on: str = "2026-09-30") -> str:
    return (
        "ignore:\n"
        "  - vulnerability: CVE-2026-14456\n"
        '    reason: "Owner: Platform. Decision: temporary acceptance. '
        "Scanner evidence: Grype reports the exact affected package. "
        "No-fix proof: upstream has not released a fixed version. "
        'Reachability: vulnerable path is not used. Exit: upgrade the runtime."\n'
        "    namespace: nvd:cpe\n"
        "    fix-state: unknown\n"
        "    match-type: cpe-match\n"
        f"    expires-on: {expires_on}\n"
        "    package:\n"
        "      name: libcrypto3\n"
        "      version: 3.5.7-r0\n"
        "      type: apk\n"
        "      location: /lib/apk/db/installed\n"
        "      upstream-name: openssl\n"
    )


def test_explicit_empty_grype_ignore_list_is_valid(tmp_path: Path) -> None:
    from prod_readiness_audit.grype_policy import validate_grype_policy

    policy = tmp_path / "grype-ignore.yaml"
    policy.write_text("ignore: []\n", encoding="utf-8")

    validate_grype_policy(policy, today=date(2026, 8, 25))


def test_exact_nonempty_grype_ignore_list_is_valid(tmp_path: Path) -> None:
    from prod_readiness_audit.grype_policy import validate_grype_policy

    policy = tmp_path / "grype-ignore.yaml"
    policy.write_text(_policy(), encoding="utf-8")

    validate_grype_policy(policy, today=date(2026, 8, 25))


def test_expired_grype_suppression_fails_closed(tmp_path: Path) -> None:
    from prod_readiness_audit.grype_policy import (
        GrypePolicyError,
        validate_grype_policy,
    )

    policy = tmp_path / "grype-ignore.yaml"
    policy.write_text(_policy(), encoding="utf-8")

    with pytest.raises(GrypePolicyError, match="expired on 2026-09-30"):
        validate_grype_policy(policy, today=date(2026, 10, 1))


@pytest.mark.parametrize(
    ("policy_text", "expected_error"),
    (
        (_policy(expires_on="20260930"), "valid ISO date"),
        (_policy().replace("    expires-on: 2026-09-30\n", ""), "expires-on"),
    ),
)
def test_missing_or_malformed_grype_expiry_fails_closed(
    tmp_path: Path, policy_text: str, expected_error: str
) -> None:
    from prod_readiness_audit.grype_policy import (
        GrypePolicyError,
        validate_grype_policy,
    )

    policy = tmp_path / "grype-ignore.yaml"
    policy.write_text(policy_text, encoding="utf-8")

    with pytest.raises(GrypePolicyError, match=expected_error):
        validate_grype_policy(policy, today=date(2026, 8, 3))


@pytest.mark.parametrize(
    ("policy_text", "expected_error"),
    (
        (_policy().replace("    reason:", "    rationale:"), "reason"),
        (_policy().replace("Owner: Platform. ", ""), "Owner"),
        (_policy().replace("Decision: temporary acceptance. ", ""), "Decision"),
        (
            _policy().replace(
                "Scanner evidence: Grype reports the exact affected package. ", ""
            ),
            "Scanner evidence",
        ),
        (
            _policy().replace(
                "No-fix proof: upstream has not released a fixed version. ", ""
            ),
            "No-fix proof",
        ),
        (
            _policy().replace("Reachability: vulnerable path is not used. ", ""),
            "Reachability",
        ),
        (_policy().replace("Exit: upgrade the runtime.", ""), "Exit"),
    ),
)
def test_grype_suppression_without_required_risk_metadata_fails_closed(
    tmp_path: Path, policy_text: str, expected_error: str
) -> None:
    from prod_readiness_audit.grype_policy import (
        GrypePolicyError,
        validate_grype_policy,
    )

    policy = tmp_path / "grype-ignore.yaml"
    policy.write_text(policy_text, encoding="utf-8")

    with pytest.raises(GrypePolicyError, match=expected_error):
        validate_grype_policy(policy, today=date(2026, 8, 3))


@pytest.mark.parametrize(
    ("policy_text", "expected_error"),
    (
        (_policy().replace("ignore:\n", "suppressions:\n"), "top-level ignore"),
        (_policy().replace("CVE-2026-14456", "GHSA-abcd-1234"), "vulnerability"),
        (_policy().replace("CVE-2026-14456", "CVE-*"), "vulnerability"),
        (_policy().replace("CVE-2026-14456", ""), "vulnerability"),
        (_policy().replace("      name: libcrypto3\n", ""), "package.name"),
        (_policy().replace("      name: libcrypto3", "      name: *"), "package.name"),
        (_policy().replace("      name: libcrypto3", "      name:"), "package.name"),
        (
            _policy().replace(
                "    package:\n      name: libcrypto3\n      version: 3.5.7-r0\n",
                "    package:\n      type: apk\n    unrelated:\n      name: libcrypto3\n      version: 3.5.7-r0\n",
            ),
            "package.name",
        ),
        (_policy().replace("      version: 3.5.7-r0\n", ""), "package.version"),
        (
            _policy().replace("      version: 3.5.7-r0", "      version: 3.5.*"),
            "package.version",
        ),
        (
            _policy().replace("      version: 3.5.7-r0", "      version:"),
            "package.version",
        ),
    ),
)
def test_grype_suppression_requires_exact_vulnerability_and_package_selectors(
    tmp_path: Path, policy_text: str, expected_error: str
) -> None:
    from prod_readiness_audit.grype_policy import (
        GrypePolicyError,
        validate_grype_policy,
    )

    policy = tmp_path / "grype-ignore.yaml"
    policy.write_text(policy_text, encoding="utf-8")

    with pytest.raises(GrypePolicyError, match=expected_error):
        validate_grype_policy(policy, today=date(2026, 8, 3))


@pytest.mark.parametrize(
    ("policy_text", "expected_error"),
    (
        (_policy().replace("    namespace: nvd:cpe\n", ""), "namespace"),
        (_policy().replace("    namespace: nvd:cpe", "    namespace: *"), "namespace"),
        (_policy().replace("    fix-state: unknown\n", ""), "fix-state"),
        (_policy().replace("    fix-state: unknown", "    fix-state: *"), "fix-state"),
        (_policy().replace("    match-type: cpe-match\n", ""), "match-type"),
        (
            _policy().replace("    match-type: cpe-match", "    match-type: *"),
            "match-type",
        ),
        (_policy().replace("      type: apk\n", ""), "package.type"),
        (_policy().replace("      type: apk", "      type: *"), "package.type"),
        (_policy().replace("      type: apk", "    type: apk"), "package.type"),
        (
            _policy().replace("      location: /lib/apk/db/installed\n", ""),
            "package.location",
        ),
        (
            _policy().replace(
                "      location: /lib/apk/db/installed",
                "      location: /lib/**",
            ),
            "package.location",
        ),
        (
            _policy().replace(
                "      location: /lib/apk/db/installed",
                "    location: /lib/apk/db/installed",
            ),
            "package.location",
        ),
        (_policy().replace("      upstream-name: openssl\n", ""), "upstream-name"),
        (
            _policy().replace(
                "      upstream-name: openssl",
                "      upstream-name: *",
            ),
            "upstream-name",
        ),
    ),
)
def test_grype_suppression_requires_all_generic_exact_evidence_selectors(
    tmp_path: Path, policy_text: str, expected_error: str
) -> None:
    from prod_readiness_audit.grype_policy import (
        GrypePolicyError,
        validate_grype_policy,
    )

    policy = tmp_path / "grype-ignore.yaml"
    policy.write_text(policy_text, encoding="utf-8")

    with pytest.raises(GrypePolicyError, match=expected_error):
        validate_grype_policy(policy, today=date(2026, 8, 3))


@pytest.mark.parametrize(
    "malformed_value",
    ("{}", "[libcrypto3]", "null", "~", "", '""', "true", "1"),
)
def test_grype_selector_requires_a_nonempty_yaml_string(
    tmp_path: Path, malformed_value: str
) -> None:
    from prod_readiness_audit.grype_policy import (
        GrypePolicyError,
        validate_grype_policy,
    )

    policy = tmp_path / "grype-ignore.yaml"
    policy.write_text(
        _policy().replace(
            "      name: libcrypto3", f"      name: {malformed_value}"
        ),
        encoding="utf-8",
    )

    with pytest.raises(GrypePolicyError, match="package.name"):
        validate_grype_policy(policy, today=date(2026, 8, 3))


@pytest.mark.parametrize(
    ("selector", "expected_error"),
    (
        ("      name: libcrypto3", "package.name"),
        (
            "      version: 3.5.7-r0",
            "package.version",
        ),
        (
            "      location: /lib/apk/db/installed",
            "package.location",
        ),
        (
            "      upstream-name: openssl",
            "package.upstream-name",
        ),
    ),
)
@pytest.mark.parametrize(
    "metacharacter", ("*", "?", "[", "]", "(", ")", "{", "}", "|", "+", "^", "$", "\\")
)
def test_grype_package_selectors_reject_pattern_metacharacters(
    tmp_path: Path,
    selector: str,
    expected_error: str,
    metacharacter: str,
) -> None:
    from prod_readiness_audit.grype_policy import (
        GrypePolicyError,
        validate_grype_policy,
    )

    policy = tmp_path / "grype-ignore.yaml"
    policy.write_text(
        _policy().replace(selector, f"{selector}{metacharacter}suffix"),
        encoding="utf-8",
    )

    with pytest.raises(GrypePolicyError, match=expected_error):
        validate_grype_policy(policy, today=date(2026, 8, 3))


def test_duplicate_grype_suppression_fails_closed(tmp_path: Path) -> None:
    from prod_readiness_audit.grype_policy import (
        GrypePolicyError,
        validate_grype_policy,
    )

    policy = tmp_path / "grype-ignore.yaml"
    policy.write_text(_policy() + _policy().removeprefix("ignore:\n"), encoding="utf-8")

    with pytest.raises(GrypePolicyError, match="duplicate"):
        validate_grype_policy(policy, today=date(2026, 8, 3))


def test_duplicate_grype_ignore_collection_fails_closed(tmp_path: Path) -> None:
    from prod_readiness_audit.grype_policy import (
        GrypePolicyError,
        validate_grype_policy,
    )

    policy = tmp_path / "grype-ignore.yaml"
    policy.write_text(_policy() + "ignore: []\n", encoding="utf-8")

    with pytest.raises(GrypePolicyError, match="exactly one top-level ignore"):
        validate_grype_policy(policy, today=date(2026, 8, 3))


@pytest.mark.parametrize("ignore_value", ("null", "{}"))
def test_non_list_grype_ignore_collection_fails_closed(
    tmp_path: Path, ignore_value: str
) -> None:
    from prod_readiness_audit.grype_policy import (
        GrypePolicyError,
        validate_grype_policy,
    )

    policy = tmp_path / "grype-ignore.yaml"
    policy.write_text(f"ignore: {ignore_value}\n", encoding="utf-8")

    with pytest.raises(GrypePolicyError, match="exactly one top-level ignore list"):
        validate_grype_policy(policy, today=date(2026, 8, 3))


def test_malformed_trailing_grype_yaml_fails_closed(tmp_path: Path) -> None:
    from prod_readiness_audit.grype_policy import (
        GrypePolicyError,
        validate_grype_policy,
    )

    policy = tmp_path / "grype-ignore.yaml"
    policy.write_text("ignore: []\ntrailing: [\n", encoding="utf-8")

    with pytest.raises(GrypePolicyError, match="valid YAML"):
        validate_grype_policy(policy, today=date(2026, 8, 3))


def test_duplicate_non_ignore_top_level_key_fails_closed(tmp_path: Path) -> None:
    from prod_readiness_audit.grype_policy import (
        GrypePolicyError,
        validate_grype_policy,
    )

    policy = tmp_path / "grype-ignore.yaml"
    policy.write_text("metadata: one\nmetadata: two\nignore: []\n", encoding="utf-8")

    with pytest.raises(GrypePolicyError, match="duplicate YAML key: metadata"):
        validate_grype_policy(policy, today=date(2026, 8, 3))


def test_prod_readiness_validates_grype_policy_before_scanning() -> None:
    from prod_readiness_audit.phases import build_prod_readiness_phases
    from prod_readiness_audit.run_state import build_run_state

    state = build_run_state(root_dir=REPO_ROOT, run_id="unit-test")
    phases = build_prod_readiness_phases(state)
    command_ids = [command.command_id for phase in phases for command in phase.commands]
    commands = {
        command.command_id: command for phase in phases for command in phase.commands
    }

    validator = commands["p4_validate_grype_policy"]
    guard_tests = commands["p2_prod_guard_pytests"]
    assert validator.required is True
    assert "prod_readiness_audit.grype_policy" in validator.command
    assert "backend/security/grype-ignore.yaml" in validator.command
    assert "test_prod_readiness_grype_policy.py" in guard_tests.command
    assert command_ids.index("p4_validate_grype_policy") < command_ids.index(
        "p4_grype_backend"
    )


def test_repository_grype_policy_is_valid_before_its_review_date() -> None:
    from prod_readiness_audit.grype_policy import validate_grype_policy

    validate_grype_policy(GRYPE_IGNORE, today=date(2026, 8, 3))


def test_repository_grype_policy_example_is_complete_and_valid(tmp_path: Path) -> None:
    from prod_readiness_audit.grype_policy import validate_grype_policy

    text = GRYPE_IGNORE.read_text(encoding="utf-8")
    example_block = text.split("# Example:\n", maxsplit=1)[1].split(
        "\n\nignore:", maxsplit=1
    )[0]
    example = "\n".join(
        line.removeprefix("# ") for line in example_block.splitlines()
    )
    policy = tmp_path / "example-grype-ignore.yaml"
    policy.write_text(f"{example}\n", encoding="utf-8")

    validate_grype_policy(policy, today=date(2026, 8, 3))


def test_repository_grype_policy_has_no_runtime_acceptances() -> None:
    import yaml

    policy = yaml.safe_load(GRYPE_IGNORE.read_text(encoding="utf-8"))
    assert policy == {"ignore": []}
