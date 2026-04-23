import subprocess
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "scripts" / "linux_lab_state.sh"


def test_lab_script_bash_syntax():
    result = subprocess.run(
        ["bash", "-n", str(SCRIPT)],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr


def test_lab_script_help_does_not_require_root():
    result = subprocess.run(
        ["bash", str(SCRIPT), "--help"],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0
    assert "Usage:" in result.stdout
