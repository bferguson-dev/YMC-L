from connector.ssh_connector import CommandResult, SSHConnector, resolve_hostname


def test_resolve_hostname_applies_domain_to_bare_host_only():
    assert resolve_hostname("linux01", "example.com") == "linux01.example.com"
    assert (
        resolve_hostname("linux01.example.com", "corp.local") == "linux01.example.com"
    )
    assert resolve_hostname("192.0.2.10", "example.com") == "192.0.2.10"
    assert resolve_hostname("2001:db8::1", "example.com") == "2001:db8::1"


def test_command_result_success_properties():
    ok = CommandResult(stdout="ok", stderr="", exit_code=0)
    failed = CommandResult(stdout="", stderr="bad", exit_code=1)
    assert ok.succeeded
    assert not ok.failed
    assert failed.failed
    assert not failed.succeeded


def test_sudo_command_wrapper_quotes_command():
    connector = SSHConnector(host="linux01", username="auditor", use_sudo=True)
    wrapped = connector._command_for_execution("printf 'hello world'")
    assert wrapped == "sudo -n sh -c 'printf '\"'\"'hello world'\"'\"''"
