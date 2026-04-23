"""Compliance runner and profile loading for YMC-L."""

import importlib.util
import logging
import re
import sys
from pathlib import Path

import yaml

from connector.ssh_connector import SSHConnector
from engine.evidence import CheckResult, HostScanResult, STATUS_ERROR, make_timestamp

logger = logging.getLogger(__name__)

_CHECKS_ROOT = Path(__file__).parent.parent / "checks"


def _discover_check_modules() -> list[Path]:
    module_files: list[Path] = []
    for py_file in sorted(_CHECKS_ROOT.rglob("*.py")):
        if py_file.name in ("__init__.py", "common.py", "registry.py"):
            continue
        module_files.append(py_file)
    return module_files


def _module_name_for_file(py_file: Path) -> str:
    relative = py_file.relative_to(_CHECKS_ROOT)
    raw = "_".join(relative.with_suffix("").parts)
    safe = re.sub(r"[^0-9a-zA-Z_]", "_", raw)
    return f"checks.dynamic.{safe}"


def _load_check_modules() -> None:
    from checks.registry import CheckRegistry

    import_failures: list[tuple[Path, Exception]] = []
    modules = _discover_check_modules()
    for module_file in modules:
        module_name = _module_name_for_file(module_file)
        try:
            if module_name in sys.modules:
                continue
            spec = importlib.util.spec_from_file_location(module_name, module_file)
            if spec is None or spec.loader is None:
                raise ImportError(f"Could not build import spec for {module_file}")
            module = importlib.util.module_from_spec(spec)
            sys.modules[module_name] = module
            spec.loader.exec_module(module)
        except Exception as exc:
            logger.error("Failed to import check module %s: %s", module_file, exc)
            import_failures.append((module_file, exc))

    if import_failures:
        failed = ", ".join(str(path) for path, _ in import_failures[:5])
        raise ImportError(f"Check module discovery failed. Failed modules: {failed}")

    logger.info(
        "Check registry loaded: %s checks registered across %s modules.",
        len(CheckRegistry),
        len(modules),
    )


_load_check_modules()


class ComplianceRunner:
    """Loads one framework profile and runs mapped checks against one host."""

    def __init__(self, profile_path: str, settings: dict):
        self.profile_path = Path(profile_path)
        self.settings = settings
        self.profile = self._load_profile()

    def _load_profile(self) -> dict:
        if not self.profile_path.exists():
            raise FileNotFoundError(f"Profile not found: {self.profile_path}")
        with open(self.profile_path, "r", encoding="utf-8") as handle:
            profile = yaml.safe_load(handle) or {}
        if "profile_name" not in profile or "checks" not in profile:
            raise ValueError(f"Invalid profile YAML: {self.profile_path}")
        return profile

    def scan(
        self,
        connector: SSHConnector,
        executed_by: str,
        tool_name: str = "YMC-L",
        tool_version: str = "0.1.0",
        progress_callback=None,
        host_label: str = "",
    ) -> HostScanResult:
        from checks.registry import CheckRegistry

        scan_start = make_timestamp()
        profile_name = self.profile["profile_name"]
        profile_id = self.profile["profile_id"]
        profile_description = self.profile.get("description", "")
        check_defs = self.profile["checks"]
        label = host_label or connector.host
        results: list[CheckResult] = []
        seen_fn_results: dict[str, CheckResult] = {}
        current = 0
        total = len(check_defs)

        for check_def in check_defs:
            check_id = check_def["check_id"]
            check_name = check_def.get("control_name", check_id)
            fn = CheckRegistry.get(check_id)
            if fn is None:
                logger.warning("No handler registered for check_id %s", check_id)
                continue

            fn_name = fn.__name__
            if fn_name in seen_fn_results and CheckRegistry.is_dedup_secondary(
                check_id
            ):
                primary = seen_fn_results[fn_name]
                secondary = self._secondary_result(primary, check_def)
                results.append(secondary)
                continue

            current += 1
            if progress_callback:
                progress_callback(
                    "check_start",
                    {
                        "check_id": check_id,
                        "check_name": check_name,
                        "host_label": label,
                        "current": current,
                        "total": total,
                    },
                )

            result = self._run_check(
                check_id,
                fn,
                connector,
                executed_by,
                tool_name,
                tool_version,
                check_def,
            )
            framework_key = profile_id
            result.framework_mappings[framework_key] = check_def["control_id"]
            if not result.check_name:
                result.check_name = check_name
            results.append(result)
            seen_fn_results[fn_name] = result

            if progress_callback:
                progress_callback(
                    "check_complete",
                    {
                        "check_id": check_id,
                        "check_name": result.check_name,
                        "host_label": label,
                        "status": result.status,
                        "finding": result.finding,
                        "current": current,
                        "total": total,
                    },
                )

        host_result = HostScanResult(
            hostname=connector.host,
            ip_address=connector.ip_address,
            scan_start_utc=scan_start,
            scan_end_utc=make_timestamp(),
            profile_name=profile_name,
            executed_by=executed_by,
            profile_id=profile_id,
            profile_description=profile_description,
            checks=results,
        )
        if progress_callback:
            progress_callback(
                "scan_complete",
                {
                    "passed": host_result.passed,
                    "failed": host_result.failed,
                    "warnings": host_result.warnings,
                    "errors": host_result.errors,
                    "compliance_pct": host_result.compliance_percentage,
                    "host_label": label,
                },
            )
        return host_result

    def _secondary_result(self, primary: CheckResult, check_def: dict) -> CheckResult:
        result = CheckResult(
            hostname=primary.hostname,
            ip_address=primary.ip_address,
            timestamp_utc=primary.timestamp_utc,
            tool_name=primary.tool_name,
            tool_version=primary.tool_version,
            executed_by=primary.executed_by,
            check_id=check_def["check_id"],
            check_name=check_def.get("control_name") or primary.check_name,
            check_category=primary.check_category,
            description=primary.description,
            framework_mappings={
                self.profile["profile_id"]: check_def["control_id"],
            },
            profile_metadata=dict(primary.profile_metadata),
            status=primary.status,
            raw_evidence=primary.raw_evidence,
            finding=primary.finding,
            remediation=primary.remediation,
            details=primary.details,
        )
        return self._apply_profile_context(result, check_def)

    def _run_check(
        self,
        check_id: str,
        fn,
        connector: SSHConnector,
        executed_by: str,
        tool_name: str,
        tool_version: str,
        check_def: dict,
    ) -> CheckResult:
        effective_settings = self._merged_settings(check_def)
        try:
            result = fn(
                connector=connector,
                settings=effective_settings,
                tool_name=tool_name,
                tool_version=tool_version,
                executed_by=executed_by,
            )
            return self._apply_profile_context(result, check_def)
        except Exception as exc:
            logger.error(
                "Unhandled exception in check %s (%s): %s",
                check_id,
                fn.__name__,
                exc,
                exc_info=True,
            )
            return CheckResult(
                hostname=connector.host,
                ip_address=connector.ip_address,
                timestamp_utc=make_timestamp(),
                tool_name=tool_name,
                tool_version=tool_version,
                executed_by=executed_by,
                check_id=check_id,
                check_name=f"Check {check_id}",
                check_category="Unknown",
                description="",
                status=STATUS_ERROR,
                finding=f"Unexpected error: {exc}",
                remediation="Review tool logs and target permissions.",
            )

    def _merged_settings(self, check_def: dict) -> dict:
        merged = dict(self.settings)
        merged.update(self.profile.get("settings_overrides", {}) or {})
        merged.update(check_def.get("settings_overrides", {}) or {})
        return merged

    def _apply_profile_context(
        self, result: CheckResult, check_def: dict
    ) -> CheckResult:
        defaults = self.profile.get("profile_defaults", {}) or {}
        metadata = {
            "profile_id": self.profile["profile_id"],
            "control_id": check_def["control_id"],
            "control_name": check_def.get("control_name"),
            "severity": check_def.get("severity", defaults.get("severity")),
            "expectation": check_def.get("expectation", defaults.get("expectation")),
            "rationale": check_def.get("rationale", defaults.get("rationale")),
            "access": check_def.get("access", defaults.get("access")),
        }
        result.profile_metadata = {
            key: value for key, value in metadata.items() if value not in (None, "")
        }

        status_overrides = dict(defaults.get("status_overrides", {}) or {})
        status_overrides.update(check_def.get("status_overrides", {}) or {})
        if result.status in status_overrides:
            original_status = result.status
            result.status = status_overrides[result.status]
            result.profile_metadata["status_override"] = {
                "from": original_status,
                "to": result.status,
                "reason": check_def.get(
                    "status_override_reason",
                    defaults.get("status_override_reason", "Profile policy override."),
                ),
            }
        return result


def list_profiles(profiles_dir: str = "profiles") -> list[str]:
    profiles_path = Path(profiles_dir)
    return sorted(path.stem for path in profiles_path.glob("*.yaml"))
