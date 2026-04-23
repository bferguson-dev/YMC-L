from pathlib import Path
from types import SimpleNamespace

import yaml

from checks.registry import CheckRegistry
from engine.runner import ComplianceRunner, list_profiles


REPO_ROOT = Path(__file__).resolve().parents[2]


class FakeConnector:
    def __init__(self, stdout: str = "", stderr: str = "", exit_code: int = 0):
        self.host = "test-host"
        self.ip_address = "192.0.2.10"
        self._stdout = stdout
        self._stderr = stderr
        self._exit_code = exit_code

    def run(self, command: str):
        return SimpleNamespace(
            stdout=self._stdout,
            stderr=self._stderr,
            exit_code=self._exit_code,
        )


def test_registered_checks_are_available():
    check_ids = CheckRegistry.all_check_ids()
    assert "SSH-002" in check_ids
    assert "AC-001" in check_ids
    assert "AU-001" in check_ids
    assert len(check_ids) >= 100


def test_profile_files_are_listed():
    profiles = list_profiles(str(REPO_ROOT / "profiles"))
    assert "nist_800_53" in profiles
    assert "pci_dss_4" in profiles
    assert "linux_baseline" in profiles
    assert "cis_ubuntu_24_04" in profiles
    assert "cis_almalinux_10" in profiles


def test_all_profile_check_ids_have_handlers():
    missing = {}
    for profile_path in sorted((REPO_ROOT / "profiles").glob("*.yaml")):
        data = yaml.safe_load(profile_path.read_text(encoding="utf-8"))
        unknown = [
            item["check_id"]
            for item in data.get("checks", [])
            if CheckRegistry.get(item["check_id"]) is None
        ]
        if unknown:
            missing[profile_path.name] = unknown
    assert missing == {}


def test_profile_shapes_have_required_metadata():
    for profile_path in sorted((REPO_ROOT / "profiles").glob("*.yaml")):
        data = yaml.safe_load(profile_path.read_text(encoding="utf-8"))
        assert data["profile_name"]
        assert data["profile_id"]
        assert data["checks"]
        for item in data["checks"]:
            assert item["check_id"]
            assert item["control_id"]
            assert item["control_name"]


def test_profile_settings_override_check_threshold(tmp_path):
    profile = {
        "profile_name": "Threshold Test",
        "profile_id": "THRESHOLD_TEST",
        "settings_overrides": {"max_password_age_days": 365},
        "checks": [
            {
                "check_id": "AC-008",
                "control_id": "TEST-AC-008",
                "control_name": "Password Maximum Age Policy",
            }
        ],
    }
    profile_path = tmp_path / "threshold.yaml"
    profile_path.write_text(yaml.safe_dump(profile), encoding="utf-8")

    runner = ComplianceRunner(str(profile_path), settings={"max_password_age_days": 90})
    result = runner.scan(
        connector=FakeConnector(stdout="PASS_MAX_DAYS=365"),
        executed_by="tester",
    )
    assert result.checks[0].status == "PASS"
    assert result.checks[0].profile_metadata["control_id"] == "TEST-AC-008"


def test_profile_status_override_applies(tmp_path):
    profile = {
        "profile_name": "Override Test",
        "profile_id": "OVERRIDE_TEST",
        "checks": [
            {
                "check_id": "CM-002",
                "control_id": "TEST-CM-002",
                "control_name": "Automatic Update Tooling",
                "status_overrides": {"WARNING": "FAIL"},
                "status_override_reason": "Profile requires auto-update tooling.",
                "severity": "high",
                "expectation": "required",
            }
        ],
    }
    profile_path = tmp_path / "override.yaml"
    profile_path.write_text(yaml.safe_dump(profile), encoding="utf-8")

    runner = ComplianceRunner(str(profile_path), settings={})
    result = runner.scan(connector=FakeConnector(stdout=""), executed_by="tester")
    check = result.checks[0]
    assert check.status == "FAIL"
    assert check.profile_metadata["severity"] == "high"
    assert check.profile_metadata["expectation"] == "required"
    assert check.profile_metadata["status_override"]["from"] == "WARNING"
