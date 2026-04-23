"""
Evidence objects shared by checks and reporters.

The shape intentionally mirrors YMC so Linux, Windows, and future VMware
platform packs can converge on one reporting contract.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional


STATUS_PASS = "PASS"
STATUS_FAIL = "FAIL"
STATUS_ERROR = "ERROR"
STATUS_WARNING = "WARNING"
STATUS_SKIP = "SKIP"


@dataclass
class CheckResult:
    """A single programmatically collected compliance evidence item."""

    hostname: str
    ip_address: str
    timestamp_utc: str
    tool_name: str
    tool_version: str
    executed_by: str
    check_id: str
    check_name: str
    check_category: str
    description: str
    framework_mappings: dict = field(default_factory=dict)
    profile_metadata: dict = field(default_factory=dict)
    status: str = STATUS_ERROR
    raw_evidence: str = ""
    finding: str = ""
    remediation: str = ""
    details: Optional[dict] = None

    def is_compliant(self) -> bool:
        return self.status == STATUS_PASS

    def to_dict(self) -> dict:
        return {
            "hostname": self.hostname,
            "ip_address": self.ip_address,
            "timestamp_utc": self.timestamp_utc,
            "tool_name": self.tool_name,
            "tool_version": self.tool_version,
            "executed_by": self.executed_by,
            "check_id": self.check_id,
            "check_name": self.check_name,
            "check_category": self.check_category,
            "description": self.description,
            "framework_mappings": self.framework_mappings,
            "profile_metadata": self.profile_metadata,
            "status": self.status,
            "raw_evidence": self.raw_evidence,
            "finding": self.finding,
            "remediation": self.remediation,
            "details": self.details,
        }


@dataclass
class HostScanResult:
    """Aggregates all check evidence for a single Linux host."""

    hostname: str
    ip_address: str
    scan_start_utc: str
    scan_end_utc: str
    profile_name: str
    executed_by: str
    profile_id: str = ""
    profile_description: str = ""
    checks: list[CheckResult] = field(default_factory=list)

    @property
    def total(self) -> int:
        return len(self.checks)

    @property
    def passed(self) -> int:
        return sum(1 for c in self.checks if c.status == STATUS_PASS)

    @property
    def failed(self) -> int:
        return sum(1 for c in self.checks if c.status == STATUS_FAIL)

    @property
    def errors(self) -> int:
        return sum(1 for c in self.checks if c.status == STATUS_ERROR)

    @property
    def warnings(self) -> int:
        return sum(1 for c in self.checks if c.status == STATUS_WARNING)

    @property
    def skipped(self) -> int:
        return sum(1 for c in self.checks if c.status == STATUS_SKIP)

    @property
    def compliance_percentage(self) -> float:
        actionable = [
            c
            for c in self.checks
            if c.status in (STATUS_PASS, STATUS_FAIL, STATUS_WARNING)
        ]
        if not actionable:
            return 0.0
        passing = sum(1 for c in actionable if c.status == STATUS_PASS)
        return round((passing / len(actionable)) * 100, 1)


def make_timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
