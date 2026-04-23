import json
from pathlib import Path

from connector.ssh_connector import CommandResult
from engine.runner import ComplianceRunner
from reporters.html_reporter import HtmlReporter
from reporters.json_reporter import JsonReporter


class FakeConnector:
    host = "linux01"
    ip_address = "192.0.2.10"

    def __init__(self, outputs):
        self.outputs = outputs
        self.commands = []

    def run(self, command):
        self.commands.append(command)
        for needle, result in self.outputs.items():
            if needle in command:
                return result
        return CommandResult(stdout="", stderr="", exit_code=0)


def test_runner_maps_framework_control(tmp_path: Path):
    profile = tmp_path / "profile.yaml"
    profile.write_text(
        "profile_name: Test Profile\n"
        "profile_id: TEST\n"
        "checks:\n"
        "  - {check_id: SSH-002, control_id: TEST-1, control_name: SSH Root}\n",
        encoding="utf-8",
    )
    connector = FakeConnector(
        {"permitrootlogin": CommandResult("permitrootlogin no", "", 0)}
    )
    result = ComplianceRunner(str(profile), {}).scan(
        connector=connector,
        executed_by="auditor",
    )
    assert result.total == 1
    assert result.passed == 1
    assert result.checks[0].framework_mappings == {"TEST": "TEST-1"}


def test_reporters_write_json_and_html(tmp_path: Path):
    profile = tmp_path / "profile.yaml"
    profile.write_text(
        "profile_name: Test Profile\n"
        "profile_id: TEST\n"
        "checks:\n"
        "  - {check_id: SSH-002, control_id: TEST-1, control_name: SSH Root}\n",
        encoding="utf-8",
    )
    connector = FakeConnector(
        {"permitrootlogin": CommandResult("permitrootlogin no", "", 0)}
    )
    result = ComplianceRunner(str(profile), {}).scan(
        connector=connector,
        executed_by="auditor",
    )
    json_path = Path(JsonReporter(tmp_path).generate(result))
    html_path = Path(HtmlReporter(tmp_path).generate(result))
    assert json.loads(json_path.read_text(encoding="utf-8"))["summary"]["passed"] == 1
    assert "Evidence Report" in html_path.read_text(encoding="utf-8")
