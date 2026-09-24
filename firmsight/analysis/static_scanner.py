"""
Static Firmware Vulnerability and Secret Scanner
Audits extracted root filesystems for hardcoded keys, credentials, SUID binaries, and backdoor configurations.
"""

import os
import re
from pathlib import Path
from typing import Dict, Any, List

class StaticScanner:
    """Performs deep security audits across extracted firmware directories."""

    PRIVATE_KEY_PATTERNS = [
        re.compile(r"-----BEGIN\s+(?:RSA|DSA|EC|OPENSSH)?\s*PRIVATE\s+KEY-----"),
        re.compile(r"-----BEGIN\s+CERTIFICATE-----"),
    ]

    CREDENTIAL_PATTERNS = [
        (re.compile(r"(?:password|passwd|pwd|secret|api_key)\s*=\s*['\"]?([^'\"\s\r\n]{4,})['\"]?", re.IGNORECASE), "Hardcoded credential assignment"),
        (re.compile(r"telnetd\s+.*-l\s+/bin/sh", re.IGNORECASE), "Insecure backdoor shell on Telnet (telnetd -l /bin/sh)"),
        (re.compile(r"nc\s+.*-e\s+/bin/sh", re.IGNORECASE), "Netcat reverse shell listener"),
    ]

    def __init__(self, rootfs_path: Path):
        self.rootfs_path = Path(rootfs_path).resolve()

    def scan(self) -> Dict[str, Any]:
        """Runs all static checks and aggregates findings."""
        findings: List[Dict[str, Any]] = []

        if not self.rootfs_path.is_dir():
            return {"findings": [], "summary": {"total": 0, "critical": 0, "high": 0}}

        findings.extend(self._scan_private_keys())
        findings.extend(self._scan_file_contents())
        findings.extend(self._scan_suid_binaries())

        # Calculate metrics
        summary = {"total": len(findings), "CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for f in findings:
            sev = f.get("severity", "LOW")
            summary[sev] = summary.get(sev, 0) + 1

        return {
            "rootfs": str(self.rootfs_path),
            "findings": findings,
            "summary": summary,
        }

    def _scan_private_keys(self) -> List[Dict[str, Any]]:
        """Finds cryptographic keys and certificates."""
        results = []
        for root, _, files in os.walk(self.rootfs_path):
            for file in files:
                fpath = Path(root) / file
                if fpath.suffix.lower() in (".pem", ".key", ".crt", ".der") or "id_rsa" in file.lower():
                    results.append({
                        "category": "Cryptographic Key / Certificate",
                        "path": str(fpath.relative_to(self.rootfs_path)),
                        "severity": "HIGH",
                        "cwe": "CWE-321",
                        "description": f"Cryptographic material packaged inside firmware: {file}",
                    })
        return results

    def _scan_file_contents(self) -> List[Dict[str, Any]]:
        """Scans shell scripts, configs, and HTML files for secrets and backdoor commands."""
        results = []
        target_exts = {".sh", ".conf", ".cfg", ".ini", ".cgi", ".html", ".js", ".json", ".xml", ".txt"}

        for root, _, files in os.walk(self.rootfs_path):
            for file in files:
                fpath = Path(root) / file
                if fpath.suffix.lower() in target_exts or "config" in file.lower():
                    try:
                        # Skip large files > 2MB
                        if fpath.stat().st_size > 2 * 1024 * 1024:
                            continue
                        content = fpath.read_text(encoding="utf-8", errors="ignore")
                        for pat, desc in self.CREDENTIAL_PATTERNS:
                            match = pat.search(content)
                            if match:
                                is_crit = "backdoor" in desc.lower() or "shell" in desc.lower()
                                results.append({
                                    "category": "Backdoor / Credential Leak",
                                    "path": str(fpath.relative_to(self.rootfs_path)),
                                    "severity": "CRITICAL" if is_crit else "HIGH",
                                    "cwe": "CWE-798" if not is_crit else "CWE-284",
                                    "description": desc,
                                    "snippet": match.group(0)[:120],
                                })
                    except Exception:
                        pass
        return results

    def _scan_suid_binaries(self) -> List[Dict[str, Any]]:
        """Checks for SUID/SGID executable binaries."""
        results = []
        for root, _, files in os.walk(self.rootfs_path):
            for file in files:
                fpath = Path(root) / file
                try:
                    mode = fpath.stat().st_mode
                    # Check S_ISUID (0o4000) or S_ISGID (0o2000)
                    if mode & 0o4000 or mode & 0o2000:
                        results.append({
                            "category": "Privileged Execution (SUID/SGID)",
                            "path": str(fpath.relative_to(self.rootfs_path)),
                            "severity": "MEDIUM",
                            "cwe": "CWE-250",
                            "description": f"Binary configured with elevated privileges (mode: {oct(mode)})",
                        })
                except Exception:
                    pass
        return results
