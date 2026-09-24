"""
Interactive HTML Security and Dynamic Analysis Report Generator
Creates standalone, dark-themed HTML audit dashboards with CWE summaries and telemetry tables.
"""

from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional

class HTMLReporter:
    """Renders comprehensive firmware dynamic & static analysis dashboards as self-contained HTML."""

    @staticmethod
    def render(report_data: Dict[str, Any], output_path: Optional[Path] = None) -> str:
        """Compiles report_data into standalone HTML."""
        target = report_data.get("target", "Firmware Target")
        gen_time = report_data.get("generated_at", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        arch = report_data.get("architecture", {})
        ext = report_data.get("extraction_stats", {})
        findings = report_data.get("findings", {})
        sensitive_files = findings.get("sensitive_files", [])
        network_anomalies = findings.get("network_anomalies", [])
        static_findings = findings.get("static_vulnerabilities", [])
        crashes = findings.get("crashes", [])

        # Calculate a threat score (0 to 100)
        score = min(100, (
            len(crashes) * 35 +
            len([f for f in static_findings if f.get("severity") == "CRITICAL"]) * 25 +
            len(network_anomalies) * 15 +
            len(sensitive_files) * 5
        ))
        risk_level = "CRITICAL" if score >= 70 else ("HIGH" if score >= 40 else ("MEDIUM" if score >= 20 else "LOW"))
        risk_color = "#ef4444" if risk_level == "CRITICAL" else ("#f97316" if risk_level == "HIGH" else ("#eab308" if risk_level == "MEDIUM" else "#10b981"))

        # Build HTML table rows
        def build_badge(sev: str) -> str:
            colors = {"CRITICAL": "#ef4444", "HIGH": "#f97316", "MEDIUM": "#eab308", "LOW": "#3b82f6"}
            c = colors.get(sev, "#64748b")
            return f'<span style="background:{c};color:#fff;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:bold;">{sev}</span>'

        sensitive_rows = "".join([
            f'<tr><td><code>{f.get("path")}</code></td><td>{f.get("description")}</td><td>{f.get("size_bytes", "DIR")} bytes</td></tr>'
            for f in sensitive_files
        ]) or '<tr><td colspan="3" style="text-align:center;color:#64748b;">No sensitive artifacts flagged</td></tr>'

        network_rows = "".join([
            f'<tr><td>{build_badge(n.get("severity", "WARN"))}</td><td><code>{n.get("source")}</code></td><td><code>{n.get("destination")}</code></td><td>{n.get("protocol")}</td><td>{n.get("info")}</td></tr>'
            for n in network_anomalies
        ]) or '<tr><td colspan="5" style="text-align:center;color:#64748b;">No anomalous network requests recorded</td></tr>'

        static_rows = "".join([
            f'<tr><td>{build_badge(s.get("severity", "LOW"))}</td><td><code>{s.get("cwe", "CWE-Unknown")}</code></td><td><code>{s.get("path")}</code></td><td>{s.get("description")}</td></tr>'
            for s in static_findings
        ]) or '<tr><td colspan="4" style="text-align:center;color:#64748b;">No static security vulnerabilities identified</td></tr>'

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>FirmSight Dynamic Audit - {target}</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background: #0f172a; color: #f8fafc; margin: 0; padding: 24px; }}
  .container {{ max-width: 1100px; margin: 0 auto; }}
  .header {{ display: flex; justify-content: space-between; align-items: center; border-bottom: 2px solid #1e293b; padding-bottom: 16px; margin-bottom: 24px; }}
  .title {{ font-size: 26px; font-weight: bold; color: #38bdf8; margin: 0; }}
  .meta {{ color: #94a3b8; font-size: 14px; margin-top: 4px; }}
  .cards {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 16px; margin-bottom: 24px; }}
  .card {{ background: #1e293b; border-radius: 8px; padding: 18px; border: 1px solid #334155; }}
  .card-label {{ color: #94a3b8; font-size: 12px; text-transform: uppercase; font-weight: bold; }}
  .card-value {{ font-size: 24px; font-weight: bold; margin-top: 6px; }}
  .section {{ background: #1e293b; border-radius: 8px; padding: 20px; border: 1px solid #334155; margin-bottom: 24px; }}
  .section-title {{ font-size: 18px; font-weight: bold; color: #38bdf8; margin-top: 0; margin-bottom: 14px; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 14px; text-align: left; }}
  th {{ background: #0f172a; color: #94a3b8; padding: 10px 12px; border-bottom: 1px solid #334155; }}
  td {{ padding: 10px 12px; border-bottom: 1px solid #334155; }}
  code {{ background: #0f172a; color: #f43f5e; padding: 2px 6px; border-radius: 4px; font-family: monospace; }}
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <div>
      <h1 class="title">🛡️ FirmSight Security Audit Dashboard</h1>
      <div class="meta">Target: <b>{target}</b> | Generated: {gen_time}</div>
    </div>
    <div style="text-align: right;">
      <span style="background:{risk_color}; color:#fff; padding:6px 16px; border-radius:20px; font-weight:bold; font-size:16px;">
        Risk: {risk_level} ({score}/100)
      </span>
    </div>
  </div>

  <div class="cards">
    <div class="card">
      <div class="card-label">CPU Architecture</div>
      <div class="card-value" style="color:#38bdf8;">{arch.get("arch", "Unknown")} ({arch.get("bitness", "?")}b)</div>
      <div style="font-size:12px;color:#94a3b8;margin-top:4px;">{arch.get("endianness", "Unknown")}-endian</div>
    </div>
    <div class="card">
      <div class="card-label">Files Extracted</div>
      <div class="card-value">{ext.get("file_count", 0)}</div>
      <div style="font-size:12px;color:#94a3b8;margin-top:4px;">Method: {ext.get("method", "N/A")}</div>
    </div>
    <div class="card">
      <div class="card-label">Sensitive Artifacts</div>
      <div class="card-value" style="color:#eab308;">{len(sensitive_files)}</div>
      <div style="font-size:12px;color:#94a3b8;margin-top:4px;">Credentials / Configurations</div>
    </div>
    <div class="card">
      <div class="card-label">Network Anomalies</div>
      <div class="card-value" style="color:#ef4444;">{len(network_anomalies)}</div>
      <div style="font-size:12px;color:#94a3b8;margin-top:4px;">Botnet / C2 Beacons</div>
    </div>
  </div>

  <div class="section">
    <h2 class="section-title">🌐 Behavioral Network Telemetry & C2 Outbound Traffic</h2>
    <table>
      <thead><tr><th>Severity</th><th>Source</th><th>Destination</th><th>Protocol</th><th>Details</th></tr></thead>
      <tbody>{network_rows}</tbody>
    </table>
  </div>

  <div class="section">
    <h2 class="section-title">🔍 Static Vulnerability & Secret Audit</h2>
    <table>
      <thead><tr><th>Severity</th><th>CWE</th><th>Path</th><th>Description</th></tr></thead>
      <tbody>{static_rows}</tbody>
    </table>
  </div>

  <div class="section">
    <h2 class="section-title">📁 Extracted Sensitive Files</h2>
    <table>
      <thead><tr><th>Path</th><th>Description</th><th>Size</th></tr></thead>
      <tbody>{sensitive_rows}</tbody>
    </table>
  </div>
</div>
</body>
</html>
"""
        if output_path:
            Path(output_path).write_text(html, encoding="utf-8")
        return html
