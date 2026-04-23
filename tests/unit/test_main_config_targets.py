from argparse import Namespace
from pathlib import Path

import main


def _args(**overrides):
    data = {
        "config": None,
        "domain": None,
        "username": None,
        "ssh_key": None,
        "profile": None,
        "format": None,
        "output_dir": None,
        "verbose": False,
        "no_color": False,
        "no_banner": False,
        "prompt_password": False,
        "use_sudo": False,
        "strict_host_key_checking": None,
        "ssh_port": None,
    }
    data.update(overrides)
    return Namespace(**data)


def test_resolve_settings_cli_overrides_defaults(monkeypatch):
    monkeypatch.delenv("COLLECTOR_USERNAME", raising=False)
    settings = main.resolve_settings(
        _args(username="auditor", profile="cis_linux", ssh_port=2222)
    )
    assert settings["username"] == "auditor"
    assert settings["profile"] == "cis_linux"
    assert settings["ssh_port"] == 2222


def test_resolve_settings_env_overrides_defaults(monkeypatch):
    monkeypatch.setenv("COLLECTOR_USERNAME", "envuser")
    monkeypatch.setenv("COLLECTOR_SSH_PORT", "2200")
    settings = main.resolve_settings(_args())
    assert settings["username"] == "envuser"
    assert settings["ssh_port"] == 2200


def test_load_targets_from_host_applies_domain():
    settings = {
        "domain": "example.com",
        "username": "auditor",
        "ssh_port": 22,
        "ssh_key": "",
    }
    targets = main.load_targets_from_host("linux01,192.0.2.10", settings)
    assert targets[0]["host"] == "linux01.example.com"
    assert targets[1]["host"] == "192.0.2.10"
    assert targets[0]["username"] == "auditor"


def test_load_targets_from_csv(tmp_path: Path):
    csv_path = tmp_path / "hosts.csv"
    csv_path.write_text(
        "domain,example.com\n"
        "host,username,label,port,ssh_key,notes\n"
        "linux01,csvuser,web,2222,~/.ssh/test,notes\n",
        encoding="utf-8",
    )
    settings = {
        "domain": "",
        "username": "",
        "ssh_port": 22,
        "ssh_key": "",
    }
    targets = main.load_targets_from_csv(csv_path, settings)
    assert targets == [
        {
            "host": "linux01.example.com",
            "username": "csvuser",
            "label": "web",
            "port": 2222,
            "ssh_key": "~/.ssh/test",
            "notes": "notes",
        }
    ]


def test_password_env_user_specific_wins(monkeypatch):
    monkeypatch.setenv("COLLECTOR_PASSWORD", "generic")
    monkeypatch.setenv("COLLECTOR_PASSWORD_AUDIT_USER", "specific")
    assert main.env_password_for("audit-user") == "specific"
