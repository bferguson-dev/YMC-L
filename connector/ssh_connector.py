"""
SSH connector for Linux targets.

Credentials are accepted in memory only and are never logged or persisted.
"""

from __future__ import annotations

import logging
import re
import shlex
import socket
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

try:
    import paramiko
except ImportError:  # pragma: no cover - exercised only without dependencies.
    paramiko = None

logger = logging.getLogger(__name__)


def resolve_hostname(host: str, domain_suffix: str = "") -> str:
    host = host.strip()
    ipv4_pattern = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
    is_ipv6 = ":" in host
    if ipv4_pattern.match(host) or is_ipv6:
        return host
    if "." in host:
        return host
    if domain_suffix:
        return f"{host}.{domain_suffix.strip().strip('.')}"
    return host


class SSHConnectionError(Exception):
    """Raised when SSH transport cannot connect or authenticate."""


class SSHExecutionError(Exception):
    """Raised when SSH command execution fails at the transport layer."""


@dataclass
class CommandResult:
    stdout: str
    stderr: str
    exit_code: int

    @property
    def succeeded(self) -> bool:
        return self.exit_code == 0

    @property
    def failed(self) -> bool:
        return self.exit_code != 0


class SSHConnector:
    """Manages one SSH session to a Linux target."""

    def __init__(
        self,
        host: str,
        username: str,
        port: int = 22,
        key_filename: str = "",
        connection_timeout: int = 30,
        read_timeout: int = 120,
        allow_agent: bool = True,
        look_for_keys: bool = True,
        strict_host_key_checking: bool = True,
        use_sudo: bool = False,
    ):
        self.host = host
        self.username = username
        self.port = port
        self.key_filename = str(Path(key_filename).expanduser()) if key_filename else ""
        self.connection_timeout = connection_timeout
        self.read_timeout = read_timeout
        self.allow_agent = allow_agent
        self.look_for_keys = look_for_keys
        self.strict_host_key_checking = strict_host_key_checking
        self.use_sudo = use_sudo
        self._client: Optional[paramiko.SSHClient] = None if paramiko else None
        self._ip_address: Optional[str] = None

    def connect(self, password: Optional[str] = None) -> None:
        if paramiko is None:
            raise SSHConnectionError(
                "paramiko is not installed. Install requirements.txt first."
            )

        logger.info("Connecting to %s via SSH", self.host)
        self._ip_address = self._resolve_ip()
        client = paramiko.SSHClient()
        client.load_system_host_keys()
        if self.strict_host_key_checking:
            client.set_missing_host_key_policy(paramiko.RejectPolicy())
        else:
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        try:
            client.connect(
                hostname=self.host,
                port=self.port,
                username=self.username,
                password=password or None,
                key_filename=self.key_filename or None,
                timeout=self.connection_timeout,
                banner_timeout=self.connection_timeout,
                auth_timeout=self.connection_timeout,
                allow_agent=self.allow_agent,
                look_for_keys=self.look_for_keys,
            )
            self._client = client
            self._verify_connection()
        except Exception as exc:
            client.close()
            self._client = None
            raise SSHConnectionError(
                f"Failed to connect to {self.host}:{self.port}: {exc}"
            ) from exc

    def disconnect(self) -> None:
        if self._client:
            self._client.close()
        self._client = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.disconnect()
        return False

    def check_ssh_available(self, password: Optional[str] = None) -> tuple[bool, str]:
        try:
            sock = socket.create_connection(
                (self.host, self.port), timeout=self.connection_timeout
            )
            sock.close()
        except (socket.timeout, ConnectionRefusedError, OSError) as exc:
            return False, f"TCP port {self.port} unreachable on {self.host}: {exc}"

        try:
            self.connect(password=password)
            result = self.run("printf SSH-OK")
            if result.stdout.strip() == "SSH-OK":
                return True, ""
            return False, f"SSH returned unexpected output: {result.stdout}"
        except Exception as exc:
            return False, str(exc)

    def run(self, command: str) -> CommandResult:
        if not self._client:
            raise SSHConnectionError(f"Not connected to {self.host}.")
        try:
            stdin, stdout, stderr = self._client.exec_command(
                self._command_for_execution(command),
                timeout=self.read_timeout,
                get_pty=False,
            )
            stdin.close()
            out = stdout.read().decode("utf-8", errors="replace").strip()
            err = stderr.read().decode("utf-8", errors="replace").strip()
            exit_code = stdout.channel.recv_exit_status()
            return CommandResult(stdout=out, stderr=err, exit_code=exit_code)
        except Exception as exc:
            raise SSHExecutionError(
                f"SSH command execution failed on {self.host}: {exc}"
            ) from exc

    @property
    def ip_address(self) -> str:
        return self._ip_address or self.host

    @property
    def is_connected(self) -> bool:
        return self._client is not None

    def _resolve_ip(self) -> str:
        try:
            return socket.gethostbyname(self.host)
        except socket.gaierror:
            return self.host

    def _verify_connection(self) -> None:
        sudo = self.use_sudo
        self.use_sudo = False
        try:
            result = self.run("true")
        finally:
            self.use_sudo = sudo
        if result.failed:
            raise SSHConnectionError(
                f"Session verification failed with exit code {result.exit_code}"
            )

    def _command_for_execution(self, command: str) -> str:
        if not self.use_sudo:
            return command
        return f"sudo -n sh -c {shlex.quote(command)}"
