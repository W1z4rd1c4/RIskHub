from __future__ import annotations

from pathlib import Path

import pytest

pytestmark = pytest.mark.contract

REPO_ROOT = Path(__file__).resolve().parents[4]
ADR_007 = REPO_ROOT / "docs/adr/ADR-007-bounded-context-taxonomy.md"
WORKFLOW_PAIRS = REPO_ROOT / "tests/backend/pytest/architecture/_bounded_context_workflow_pairs.toml"


def _heading_sections() -> dict[tuple[str, ...], list[str]]:
    sections: dict[tuple[str, ...], list[str]] = {}
    stack: list[str] = []
    current: tuple[str, ...] | None = None

    for line in ADR_007.read_text(encoding="utf-8").splitlines():
        if line.startswith("#"):
            level = len(line) - len(line.lstrip("#"))
            title = line[level:].strip()
            stack = stack[: level - 1]
            stack.append(title)
            current = tuple(stack)
            sections.setdefault(current, [])
            continue
        if current is not None:
            sections[current].append(line)

    return sections


def _classification_rows() -> dict[str, dict[str, str]]:
    sections = _heading_sections()
    lines = sections[(
        "ADR-007 Bounded Context Taxonomy",
        "Amendment 1 — Read-Shape, Workflow-Paired, Adapter, and Cross-cutting Contexts",
        "Classification Table",
    )]
    table_lines = [line for line in lines if line.startswith("|")]
    header = [cell.strip() for cell in table_lines[0].strip("|").split("|")]
    rows: dict[str, dict[str, str]] = {}
    for line in table_lines[2:]:
        cells = [cell.strip() for cell in line.strip("|").split("|")]
        row = dict(zip(header, cells, strict=True))
        rows[row["Package"].strip("`")] = row
    return rows


def test_amendment_section_exists() -> None:
    sections = _heading_sections()
    assert (
        "ADR-007 Bounded Context Taxonomy",
        "Amendment 1 — Read-Shape, Workflow-Paired, Adapter, and Cross-cutting Contexts",
    ) in sections


def test_amendment_uses_cross_cutting_not_core() -> None:
    rows = _classification_rows()
    assert rows["_authorization_capabilities"]["Category"] == "Cross-cutting"
    assert rows["_config"]["Category"] == "Cross-cutting"
    assert "Core" not in {row["Category"] for row in rows.values()}


def test_amendment_lists_thirteen_workflow_pairs() -> None:
    rows = _classification_rows()
    assert rows["_orphaned_items"]["Category"] == "Workflow-paired (`_identity_access_lifecycle`)"
    assert rows["_notification_inbox"]["Category"] == "Workflow-paired (`_identity_access_lifecycle`)"
    assert rows["_ict_register_lifecycle"]["Category"] == "Workflow-paired (`_vendor_governance`)"
    assert rows["_local_auth"]["Category"] == "Workflow-paired (`_auth_session_workflow`)"
    assert WORKFLOW_PAIRS.read_text().count("[[pairs]]") == 13


def test_amendment_cross_references_graph_directory_post_61() -> None:
    row = _classification_rows()["_graph_directory"]
    assert row["Category"] == "Adapter"
    assert row["Enforcement TOML"] == "`_bounded_context_adapters.toml`"
