from __future__ import annotations

import ast
from pathlib import Path

import pytest

pytestmark = pytest.mark.contract

REPO_ROOT = Path(__file__).resolve().parents[4]
REFRESH_ENDPOINT = REPO_ROOT / "backend/app/api/v1/endpoints/auth/refresh.py"
REFRESH_SERVICE = REPO_ROOT / "backend/app/services/_auth_session/refresh.py"


def _function_source(path: Path, function_name: str) -> str:
    source = path.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(path))
    function = next(
        node
        for node in tree.body
        if isinstance(node, ast.AsyncFunctionDef) and node.name == function_name
    )
    return ast.get_source_segment(source, function) or ""


def test_refresh_rotation_takes_user_lock_before_refresh_row_update() -> None:
    source = _function_source(REFRESH_ENDPOINT, "refresh_session")

    assert source.index("await lock_refresh_rotation_user(") < source.index(
        "update(RefreshToken)"
    )


def test_replay_containment_order_is_locked_and_workflow_committed() -> None:
    source = _function_source(REFRESH_SERVICE, "_contain_rotated_refresh_replay")

    ordered_steps = [
        "for_update=True",
        "select(RefreshToken)",
        "await _find_active_rotated_descendant(",
        "confirmed = await db.execute(",
        "await invalidate_user_sessions(",
        "await record_session_audit_plan(",
        "await commit_refresh_session(db)",
    ]
    positions = [source.index(step) for step in ordered_steps]

    assert positions == sorted(positions)


def test_ordinary_rotation_lock_rereads_user_state() -> None:
    source = _function_source(REFRESH_SERVICE, "lock_refresh_rotation_user")

    assert "for_update=True" in source
    assert "user.token_version != expected_token_version" in source


def test_every_failure_refresh_revoke_uses_the_user_first_lock_primitive() -> None:
    revoke_source = _function_source(REFRESH_SERVICE, "_revoke_refresh_row")
    resolution_source = _function_source(REFRESH_SERVICE, "resolve_refresh_session")

    assert revoke_source.index("for_update=True") < revoke_source.index(
        "update(RefreshToken)"
    )
    assert resolution_source.count("await _revoke_refresh_row(") == 3


def test_shared_replay_invalidation_still_bumps_and_revokes_without_commit() -> None:
    path = REPO_ROOT / "backend/app/services/_auth_session_workflow/authority.py"
    source = _function_source(path, "invalidate_user_sessions")
    revoke = _function_source(path, "revoke_user_refresh_tokens")
    assert source.index("user.token_version += 1") < source.index(
        "await revoke_user_refresh_tokens("
    )
    assert "RefreshToken.revoked_at.is_(None)" in revoke
    assert "RefreshToken.user_id == user_id" in revoke
    assert "commit(" not in source + revoke
