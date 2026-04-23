import subprocess
import sys


def run_cli(*args):
    return subprocess.run(
        [sys.executable, "main.py", *args],
        check=False,
        capture_output=True,
        text=True,
    )


def test_list_profiles_smoke():
    result = run_cli("--list-profiles")
    assert result.returncode == 0
    assert "nist_800_53" in result.stdout
    assert "cis_ubuntu_24_04" in result.stdout


def test_list_checks_smoke():
    result = run_cli("--list-checks")
    assert result.returncode == 0
    assert "SSH-002" in result.stdout


def test_missing_target_returns_usage_error():
    result = run_cli("--profile", "linux_baseline")
    assert result.returncode == 2
    assert "Provide --host or --csv" in result.stdout
