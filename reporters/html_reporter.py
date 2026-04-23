"""Audit evidence HTML report output."""

import html
import re

from engine.evidence import (
    STATUS_ERROR,
    STATUS_FAIL,
    STATUS_PASS,
    STATUS_WARNING,
    HostScanResult,
)
from reporters.base_reporter import BaseReporter


STATUS_CONFIG = {
    STATUS_PASS: {"label": "PASS", "color": "#2d6a2d", "bg": "#e8f5e8"},
    STATUS_FAIL: {"label": "FAIL", "color": "#8b0000", "bg": "#fdecea"},
    STATUS_WARNING: {"label": "WARN", "color": "#7d5a00", "bg": "#fff8e1"},
    STATUS_ERROR: {"label": "ERROR", "color": "#4a4a4a", "bg": "#f5f5f5"},
}


class HtmlReporter(BaseReporter):
    def generate(self, scan_result: HostScanResult) -> str:
        filepath = self._make_filename(scan_result, "html")
        with open(filepath, "w", encoding="utf-8") as handle:
            handle.write(self._build_html(scan_result))
        return str(filepath)

    def _build_html(self, result: HostScanResult) -> str:
        tool_name = result.checks[0].tool_name if result.checks else "YMC-L"
        tool_version = result.checks[0].tool_version if result.checks else "0.1.0"
        rows = []
        for check in result.checks:
            cfg = STATUS_CONFIG.get(check.status, STATUS_CONFIG[STATUS_ERROR])
            evidence_id = "ev_" + re.sub(r"[^0-9a-zA-Z_]", "_", check.check_id)
            badge_style = (
                f"background:{cfg['bg']};color:{cfg['color']};"
                f"border:1px solid {cfg['color']}"
            )
            mappings = "<br>".join(
                f"<span class='mapping'>{self._esc(k)}: {self._esc(v)}</span>"
                for k, v in check.framework_mappings.items()
            )
            raw = self._esc(check.raw_evidence or "(no output captured)")
            profile_meta = check.profile_metadata or {}
            profile_summary = []
            for label, key in [
                ("Severity", "severity"),
                ("Expectation", "expectation"),
                ("Access", "access"),
            ]:
                if profile_meta.get(key):
                    profile_summary.append(
                        f"<strong>{label}:</strong> {self._esc(profile_meta[key])}"
                    )
            if profile_meta.get("rationale"):
                profile_summary.append(
                    "<strong>Profile Rationale:</strong> "
                    f"{self._esc(profile_meta['rationale'])}"
                )
            if profile_meta.get("status_override"):
                override = profile_meta["status_override"]
                profile_summary.append(
                    "<strong>Status Override:</strong> "
                    f"{self._esc(override.get('from'))} -> "
                    f"{self._esc(override.get('to'))} "
                    f"({self._esc(override.get('reason', ''))})"
                )
            rows.append(
                f"""
                <tr class="check-row" onclick="toggle('{evidence_id}')">
                    <td><code>{self._esc(check.check_id)}</code></td>
                    <td><span class="badge" style="{badge_style}">
                      {cfg["label"]}
                    </span></td>
                    <td>{self._esc(check.check_category)}</td>
                    <td>{self._esc(check.check_name)}</td>
                    <td>{self._esc(check.finding)}</td>
                    <td>{mappings}</td>
                </tr>
                <tr id="{evidence_id}" class="evidence-row" style="display:none">
                    <td colspan="6">
                        <div class="evidence-block">
                            <p><strong>Description:</strong>
                              {self._esc(check.description)}
                            </p>
                            <p><strong>Timestamp (UTC):</strong>
                              {self._esc(check.timestamp_utc)}
                              <strong>Run By:</strong>
                              {self._esc(check.executed_by)}
                            </p>
                            <p>{"<br>".join(profile_summary)}</p>
                            <strong>Raw Evidence:</strong>
                            <pre class="raw-evidence">{raw}</pre>
                            <strong>Remediation:</strong>
                            <pre>{self._esc(check.remediation or "(none)")}</pre>
                        </div>
                    </td>
                </tr>
                """
            )

        pass_pct = result.compliance_percentage
        bar_color = (
            "#2d6a2d" if pass_pct >= 80 else "#e67e00" if pass_pct >= 60 else "#8b0000"
        )
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>{self._esc(tool_name)} Report - {self._esc(result.hostname)}</title>
  <style>
    * {{ box-sizing: border-box; }}
    body {{
      font-family: Arial, sans-serif;
      font-size: 13px;
      color: #222;
      background: #f4f4f4;
      padding: 20px;
    }}
    .container {{
      max-width: 1400px;
      margin: 0 auto;
      background: white;
      padding: 30px;
      border: 1px solid #ddd;
    }}
    h1 {{ color: #003366; font-size: 22px; margin: 0 0 6px; }}
    .meta-grid {{
      display: grid;
      grid-template-columns: repeat(3, 1fr);
      gap: 10px;
      margin: 18px 0;
    }}
    .meta-item {{ background: #f8f9fa; border: 1px solid #ddd; padding: 10px; }}
    .label {{ color: #555; font-size: 11px; text-transform: uppercase; }}
    .value {{ font-weight: 700; margin-top: 3px; }}
    .stats {{ display: flex; gap: 10px; margin: 18px 0; }}
    .stat {{ flex: 1; padding: 12px; border: 1px solid #ddd; text-align: center; }}
    .num {{ font-size: 24px; font-weight: 700; }}
    .bar-outer {{ background: #ddd; height: 18px; margin-bottom: 18px; }}
    .bar-inner {{ background: {bar_color}; height: 18px; width: {pass_pct}%; }}
    table {{ width: 100%; border-collapse: collapse; }}
    th {{ background: #003366; color: white; padding: 8px; text-align: left; }}
    td {{ padding: 8px; border-bottom: 1px solid #eee; vertical-align: top; }}
    .check-row:hover {{ background: #f0f4ff; cursor: pointer; }}
    .badge {{
      display: inline-block;
      border-radius: 3px;
      padding: 2px 7px;
      font-size: 11px;
      font-weight: 700;
    }}
    .mapping {{
      display: inline-block;
      background: #eef;
      border: 1px solid #cce;
      margin: 1px 0;
      padding: 1px 5px;
    }}
    .evidence-block {{ background: #fafafa; padding: 14px; }}
    pre {{ white-space: pre-wrap; overflow-x: auto; }}
    .raw-evidence {{ background: #1e1e1e; color: #d4d4d4; padding: 12px; }}
  </style>
  <script>
    function toggle(id) {{
      var el = document.getElementById(id);
      el.style.display = (el.style.display === 'none') ? 'table-row' : 'none';
    }}
  </script>
</head>
<body>
<div class="container">
  <h1>{self._esc(tool_name)} v{self._esc(tool_version)} - Evidence Report</h1>
  <p>Automated Linux SSH evidence for programmatically checkable controls.</p>
  <div class="meta-grid">
    <div class="meta-item"><div class="label">Target Host</div>
      <div class="value">{self._esc(result.hostname)}</div></div>
    <div class="meta-item"><div class="label">IP Address</div>
      <div class="value">{self._esc(result.ip_address)}</div></div>
    <div class="meta-item"><div class="label">Profile</div>
      <div class="value">{self._esc(result.profile_name)}</div></div>
    <div class="meta-item"><div class="label">Profile ID</div>
      <div class="value">{self._esc(result.profile_id)}</div></div>
    <div class="meta-item"><div class="label">Started UTC</div>
      <div class="value">{self._esc(result.scan_start_utc)}</div></div>
    <div class="meta-item"><div class="label">Ended UTC</div>
      <div class="value">{self._esc(result.scan_end_utc)}</div></div>
    <div class="meta-item"><div class="label">Executed By</div>
      <div class="value">{self._esc(result.executed_by)}</div></div>
  </div>
  <div class="stats">
    <div class="stat"><div class="num">{result.passed}</div><div>Passed</div></div>
    <div class="stat"><div class="num">{result.failed}</div><div>Failed</div></div>
    <div class="stat"><div class="num">{result.warnings}</div><div>Warnings</div></div>
    <div class="stat"><div class="num">{result.errors}</div><div>Errors</div></div>
  </div>
  <div class="bar-outer"><div class="bar-inner"></div></div>
  <table>
    <thead><tr>
      <th>Check</th><th>Status</th><th>Category</th><th>Name</th>
      <th>Finding</th><th>Framework Controls</th>
    </tr></thead>
    <tbody>{"".join(rows)}</tbody>
  </table>
</div>
</body>
</html>"""

    def _esc(self, value) -> str:
        return html.escape(str(value), quote=True)
