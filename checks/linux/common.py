"""Shared helpers used by Linux check modules."""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import Callable

from checks.registry import register_check
from connector.ssh_connector import SSHConnector, SSHExecutionError
from engine.evidence import (
    STATUS_ERROR,
    STATUS_FAIL,
    STATUS_PASS,
    STATUS_SKIP,
    STATUS_WARNING,
    CheckResult,
    make_timestamp,
)

__all__ = [
    "CheckResult",
    "CommandCheckSpec",
    "Evaluator",
    "SSHConnector",
    "SSHExecutionError",
    "STATUS_ERROR",
    "STATUS_FAIL",
    "STATUS_PASS",
    "STATUS_SKIP",
    "STATUS_WARNING",
    "base_result",
    "bool_setting",
    "int_setting",
    "logging",
    "register_command_check",
    "register_check",
    "str_list_setting",
]

Evaluator = Callable[[str, int, dict], tuple[str, str, str, dict | None]]


@dataclass(frozen=True)
class CommandCheckSpec:
    check_id: str
    check_name: str
    category: str
    description: str
    command: str
    remediation: str
    evaluator: Evaluator


def base_result(
    connector: SSHConnector,
    check_id: str,
    check_name: str,
    description: str,
    category: str,
    tool_name: str,
    tool_version: str,
    executed_by: str,
) -> CheckResult:
    return CheckResult(
        hostname=connector.host,
        ip_address=connector.ip_address,
        timestamp_utc=make_timestamp(),
        tool_name=tool_name,
        tool_version=tool_version,
        executed_by=executed_by,
        check_id=check_id,
        check_name=check_name,
        check_category=category,
        description=description,
    )


def register_command_check(spec: CommandCheckSpec):
    def check(
        connector: SSHConnector,
        settings: dict,
        tool_name: str,
        tool_version: str,
        executed_by: str,
    ) -> CheckResult:
        result = base_result(
            connector,
            spec.check_id,
            spec.check_name,
            spec.description,
            spec.category,
            tool_name,
            tool_version,
            executed_by,
        )
        try:
            cmd = connector.run(spec.command)
            raw = cmd.stdout or cmd.stderr
            if cmd.stdout and cmd.stderr:
                raw = f"{cmd.stdout}\n--- STDERR ---\n{cmd.stderr}"
            result.raw_evidence = raw
            status, finding, remediation, details = spec.evaluator(
                raw,
                cmd.exit_code,
                settings,
            )
            result.status = status
            result.finding = finding
            result.remediation = remediation or spec.remediation
            result.details = details
        except SSHExecutionError as exc:
            result.status = STATUS_ERROR
            result.raw_evidence = str(exc)
            result.finding = f"Check execution failed: {exc}"
            result.remediation = "Verify SSH connectivity and account permissions."
        return result

    check.__name__ = f"check_{re.sub(r'[^0-9a-zA-Z_]', '_', spec.check_id).lower()}"
    register_check(spec.check_id)(check)
    return check


def bool_setting(settings: dict, key: str, default: bool = False) -> bool:
    value = settings.get(key, default)
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "on"}
    return bool(value)


def int_setting(settings: dict, key: str, default: int) -> int:
    try:
        return int(settings.get(key, default))
    except (TypeError, ValueError):
        return default


def str_list_setting(settings: dict, key: str, default: list[str]) -> list[str]:
    value = settings.get(key, default)
    if isinstance(value, str):
        return [item.strip() for item in value.split(",") if item.strip()]
    if isinstance(value, (list, tuple, set)):
        return [str(item).strip() for item in value if str(item).strip()]
    return [str(item).strip() for item in default if str(item).strip()]
