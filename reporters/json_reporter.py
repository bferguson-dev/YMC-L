"""Structured JSON report output."""

import json

from engine.evidence import HostScanResult
from reporters.base_reporter import BaseReporter


class JsonReporter(BaseReporter):
    def generate(self, scan_result: HostScanResult) -> str:
        output = {
            "report_metadata": {
                "tool_name": scan_result.checks[0].tool_name
                if scan_result.checks
                else "YMC-L",
                "tool_version": scan_result.checks[0].tool_version
                if scan_result.checks
                else "0.1.0",
                "profile_name": scan_result.profile_name,
                "profile_id": scan_result.profile_id,
                "profile_description": scan_result.profile_description,
                "hostname": scan_result.hostname,
                "ip_address": scan_result.ip_address,
                "executed_by": scan_result.executed_by,
                "scan_start_utc": scan_result.scan_start_utc,
                "scan_end_utc": scan_result.scan_end_utc,
            },
            "summary": {
                "total_checks": scan_result.total,
                "passed": scan_result.passed,
                "failed": scan_result.failed,
                "warnings": scan_result.warnings,
                "errors": scan_result.errors,
                "skipped": scan_result.skipped,
                "compliance_percentage": scan_result.compliance_percentage,
            },
            "checks": [check.to_dict() for check in scan_result.checks],
        }
        filepath = self._make_filename(scan_result, "json")
        with open(filepath, "w", encoding="utf-8") as handle:
            json.dump(output, handle, indent=2, default=str)
        return str(filepath)
