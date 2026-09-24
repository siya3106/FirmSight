"""
Automated Security and Dynamic Analysis Report Generator
Produces structured audit reports with CWE mappings and behavioral summaries.
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional
from .html_reporter import HTMLReporter

class SecurityReporter:
    """Generates structured JSON, Markdown, and interactive HTML audit reports for analyzed firmware."""

    CWE_MAPPINGS = {
        "empty_password": {
            "id": "CWE-258",
            "name": "Empty Password in Configuration",
            "severity": "CRITICAL",
        },
        "hardcoded_root": {
            "id": "CWE-798",
            "name": "Use of Hard-coded Credentials",
            "severity": "HIGH",
        },
        "c2_beacon": {
            "id": "CWE-319",
            "name": "Cleartext Transmission of Sensitive Information / C2 Communication",
            "severity": "CRITICAL",
        },
        "unencrypted_http": {
            "id": "CWE-319",
            "name": "Cleartext HTTP Management Interface",
            "severity": "MEDIUM",
        },
    }

    def __init__(self, target_name: str = "Firmware Image"):
        self.target_name = target_name
        self.timestamp = datetime.now().isoformat()
        self.architecture_info: Dict[str, Any] = {}
        self.extraction_info: Dict[str, Any] = {}
        self.network_findings: List[Dict[str, Any]] = []
        self.sensitive_files: List[Dict[str, Any]] = []
        self.static_findings: List[Dict[str, Any]] = []
        self.crashes: List[Dict[str, Any]] = []

    def set_extraction_results(self, extraction_report: Dict[str, Any]):
        self.extraction_info = extraction_report
        self.sensitive_files = extraction_report.get("sensitive_files", [])

    def set_arch_results(self, arch_report: Dict[str, Any]):
        self.architecture_info = arch_report

    def set_static_findings(self, static_report: Dict[str, Any]):
        self.static_findings = static_report.get("findings", [])

    def add_crash_event(self, crash_event: Dict[str, Any]):
        self.crashes.append(crash_event)

    def add_network_event(self, event: Dict[str, Any]):
        if event.get("flagged"):
            self.network_findings.append(event)

    def to_dict(self) -> Dict[str, Any]:
        """Returns unified dictionary of all findings."""
        return {
            "target": self.target_name,
            "generated_at": self.timestamp,
            "architecture": self.architecture_info,
            "extraction_stats": {
                "file_count": self.extraction_info.get("file_count", 0),
                "total_bytes": self.extraction_info.get("total_bytes", 0),
                "method": self.extraction_info.get("method", "N/A"),
            },
            "findings": {
                "sensitive_files": self.sensitive_files,
                "network_anomalies": self.network_findings,
                "static_vulnerabilities": self.static_findings,
                "crashes": self.crashes,
            },
        }

    def generate_json(self, output_file: Optional[Path] = None) -> str:
        """Exports the full audit as JSON."""
        res = json.dumps(self.to_dict(), indent=2)
        if output_file:
            Path(output_file).write_text(res, encoding="utf-8")
        return res

    def generate_html(self, output_file: Optional[Path] = None) -> str:
        """Exports the full audit as an interactive HTML dashboard."""
        return HTMLReporter.render(self.to_dict(), output_path=output_file)

    def generate_markdown(self, output_file: Optional[Path] = None) -> str:
        """Generates a professional Markdown audit report."""
        md = []
        md.append(f"# FirmSight Dynamic Analysis Report: {self.target_name}\n")
        md.append(f"**Generated:** `{self.timestamp}`\n")
        md.append("## 1. Executive Summary\n")
        md.append(
            "This report summarizes the dynamic analysis and extraction results obtained by **FirmSight**. "
            "The target firmware was unpacked, its foreign CPU architecture analyzed, and runtime emulation telemetry recorded.\n"
        )

        md.append("## 2. Firmware Architecture & Target Emulation\n")
        if self.architecture_info:
            md.append(f"- **CPU Architecture:** {self.architecture_info.get('arch', 'Unknown')}")
            md.append(f"- **Bitness:** {self.architecture_info.get('bitness', 'N/A')}-bit")
            md.append(f"- **Endianness:** {self.architecture_info.get('endianness', 'N/A')}")
            md.append(f"- **Recommended QEMU Emulator:** `{self.architecture_info.get('qemu_target', 'N/A')}`\n")
        else:
            md.append("- *No valid ELF architecture detected.*\n")

        md.append("## 3. Filesystem Extraction & Sensitive Artifacts\n")
        if self.sensitive_files:
            md.append("| Path | Finding Description | Size |")
            md.append("| :--- | :--- | :--- |")
            for sf in self.sensitive_files:
                md.append(f"| `{sf['path']}` | {sf['description']} | {sf.get('size_bytes', 'DIR')} |")
            md.append("")
        else:
            md.append("- *No sensitive configuration files detected.*\n")

        md.append("## 4. Static Firmware Vulnerability Audit\n")
        if self.static_findings:
            md.append("| Severity | CWE | Path | Description |")
            md.append("| :--- | :--- | :--- | :--- |")
            for st in self.static_findings:
                md.append(f"| **{st.get('severity')}** | `{st.get('cwe')}` | `{st.get('path')}` | {st.get('description')} |")
            md.append("")
        else:
            md.append("- *No static vulnerabilities detected.*\n")

        md.append("## 5. Network Behavioral Heuristics & C2 Telemetry\n")
        if self.network_findings:
            md.append("| Source | Destination | Protocol | Severity | Details |")
            md.append("| :--- | :--- | :--- | :--- | :--- |")
            for nf in self.network_findings:
                md.append(f"| `{nf.get('source')}` | `{nf.get('destination')}` | `{nf.get('protocol')}` | **{nf.get('severity')}** | {nf.get('info')} |")
            md.append("")
        else:
            md.append("- *No suspicious network anomalies detected during dynamic monitoring.*\n")

        if self.crashes:
            md.append("## 6. Dynamic Fault & Crash Telemetry\n")
            md.append("| Signal | Description | Severity | CWE | Registers |")
            md.append("| :--- | :--- | :--- | :--- | :--- |")
            for cr in self.crashes:
                reg_str = ", ".join([f"{k}={v}" for k, v in cr.get("registers", {}).items()]) or "N/A"
                md.append(f"| `{cr.get('signal')}` | {cr.get('description')} | **{cr.get('severity')}** | `{cr.get('cwe')}` | {reg_str} |")
            md.append("")

        content = "\n".join(md)
        if output_file:
            Path(output_file).write_text(content, encoding="utf-8")
        return content
