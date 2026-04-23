import os

import pytest

from connector.ssh_connector import SSHConnector


@pytest.mark.integration
def test_live_ssh_precheck_when_environment_is_configured():
    host = os.environ.get("YMC_L_LIVE_HOST")
    username = os.environ.get("YMC_L_LIVE_USERNAME")
    if not host or not username:
        pytest.skip("Set YMC_L_LIVE_HOST and YMC_L_LIVE_USERNAME for live SSH test.")

    connector = SSHConnector(
        host=host,
        username=username,
        port=int(os.environ.get("YMC_L_LIVE_PORT", "22")),
        key_filename=os.environ.get("YMC_L_LIVE_SSH_KEY", ""),
        strict_host_key_checking=os.environ.get(
            "YMC_L_LIVE_STRICT_HOST_KEY_CHECKING",
            "true",
        ).lower()
        in {"1", "true", "yes", "on"},
    )
    ok, reason = connector.check_ssh_available(
        password=os.environ.get("YMC_L_LIVE_PASSWORD") or None
    )
    connector.disconnect()
    assert ok, reason
