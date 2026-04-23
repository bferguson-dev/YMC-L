"""Shared reporter helpers."""

import re
from pathlib import Path

from engine.evidence import HostScanResult


class BaseReporter:
    def __init__(self, output_dir: str | Path):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def _make_filename(self, scan_result: HostScanResult, extension: str) -> Path:
        host = self._slug(scan_result.hostname)
        profile = self._slug(scan_result.profile_name)
        return self.output_dir / f"{host}_{profile}.{extension}"

    def _slug(self, text: str) -> str:
        return re.sub(r"[^a-zA-Z0-9]+", "_", text).strip("_").lower() or "host"

    def generate(self, scan_result: HostScanResult) -> str:
        raise NotImplementedError
