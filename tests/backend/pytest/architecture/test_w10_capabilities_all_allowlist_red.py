from __future__ import annotations

import ast
import tomllib
from datetime import date
from pathlib import Path

import pytest

pytestmark = pytest.mark.contract

REPO_ROOT = Path(__file__).resolve().parents[4]
CAPABILITIES_INIT = REPO_ROOT / "backend/app/services/_authorization_capabilities/__init__.py"
ALLOWLIST_PATH = REPO_ROOT / "tests/backend/pytest/architecture/_capabilities_all_allowlist.toml"


def _module_all_names(path: Path) -> list[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    for node in tree.body:
        if not isinstance(node, ast.Assign):
            continue
        if not any(isinstance(target, ast.Name) and target.id == "__all__" for target in node.targets):
            continue
        if not isinstance(node.value, ast.List):
            continue
        names: list[str] = []
        for element in node.value.elts:
            if isinstance(element, ast.Constant) and isinstance(element.value, str):
                names.append(element.value)
        return names
    raise AssertionError("__all__ assignment not found")


def test_capabilities_public_exports_match_allowlist() -> None:
    allowlist = tomllib.loads(ALLOWLIST_PATH.read_text(encoding="utf-8"))
    public_names = [entry["name"] for entry in allowlist["public_names"]]

    assert _module_all_names(CAPABILITIES_INIT) == public_names


def test_capabilities_public_exports_allowlist_has_minimal_schema() -> None:
    allowlist = tomllib.loads(ALLOWLIST_PATH.read_text(encoding="utf-8"))
    for entry in allowlist["public_names"]:
        assert set(entry) == {"name", "expires_at"}, entry
        assert date.fromisoformat(entry["expires_at"]) >= date.today(), entry
