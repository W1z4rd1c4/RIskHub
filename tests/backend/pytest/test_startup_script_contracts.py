from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
COMPOSE_SCRIPT = REPO_ROOT / "scripts" / "compose.sh"


def _run_compose(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [str(COMPOSE_SCRIPT), *args],
        cwd=REPO_ROOT,
        check=False,
        capture_output=True,
        text=True,
        env=os.environ.copy(),
    )


def test_compose_help_entrypoints_exit_zero() -> None:
    for args in (["--help"], ["-h"], ["help"]):
        result = _run_compose(*args)
        output = f"{result.stdout}\n{result.stderr}"
        assert result.returncode == 0, output
        assert "Usage:" in result.stdout


def test_compose_without_command_exits_nonzero() -> None:
    result = _run_compose()
    output = f"{result.stdout}\n{result.stderr}"
    assert result.returncode != 0, output
    assert "Usage:" in result.stdout


@pytest.mark.parametrize("failures, succeeds", [(2, True), (100, False)])
def test_compose_smoke_waits_for_frontend_but_remains_bounded(tmp_path, failures, succeeds) -> None:
    """Exercise the real onboarding command with deterministic transport startup."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    docker_log = tmp_path / "docker.log"
    probe_log = tmp_path / "probe.log"
    counter = tmp_path / "attempts"
    scripts = {
        "docker": '#!/usr/bin/env bash\nprintf "%s\\n" "$*" >> "$DOCKER_LOG"\n'
        'if [[ "$1 $2" == "container inspect" ]]; then exit 1; fi\nexit 0\n',
        "sleep": "#!/usr/bin/env bash\nexit 0\n",
        "curl": '#!/usr/bin/env bash\nprintf "%s\\n" "$*" >> "$PROBE_LOG"\n'
        'if [[ "$*" == *"localhost:80/login"* ]]; then\n'
        '  count=0; [[ ! -f "$COUNTER" ]] || read -r count < "$COUNTER"\n'
        '  count=$((count + 1)); printf "%s\\n" "$count" > "$COUNTER"\n'
        '  if (( count <= FAILURES )); then exit 56; fi\n'
        'fi\nexit 0\n',
    }
    for name, content in scripts.items():
        path = bin_dir / name
        path.write_text(content)
        path.chmod(0o755)
    env = {**os.environ, "PATH": f"{bin_dir}:{os.environ['PATH']}",
           "DOCKER_LOG": str(docker_log), "PROBE_LOG": str(probe_log),
           "COUNTER": str(counter), "FAILURES": str(failures)}
    result = subprocess.run(
        [str(COMPOSE_SCRIPT), "up", "--no-build"], cwd=REPO_ROOT,
        env=env, capture_output=True, text=True, check=False, timeout=10,
    )
    assert (result.returncode == 0) is succeeds, result.stdout + result.stderr
    assert int(counter.read_text()) == (3 if succeeds else 12)
    if succeeds:
        assert "Startup complete" in result.stdout
    else:
        assert "Login page not reachable" in result.stderr
        assert "Startup complete" not in result.stdout
        assert "logs riskhub-frontend" in docker_log.read_text()
    probes = probe_log.read_text().splitlines()
    assert all("--connect-timeout 2" in probe and "--max-time 5" in probe for probe in probes)
