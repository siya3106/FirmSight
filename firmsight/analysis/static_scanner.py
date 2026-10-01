"""
Static Firmware Vulnerability and Secret Scanner
Audits extracted root filesystems for hardcoded keys, high-entropy tokens, credentials,
SUID binaries, default IoT vendor passwords, and backdoor configurations.
"""

import math
import os
import re
from collections import Counter
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple

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

    # Common IoT default credentials & vendor factory strings
    IOT_VENDOR_DEFAULTS = {
        "admin", "password", "1234", "123456", "root", "default", "guest",
        "superadmin", "support", "telnetadmin", "smcadmin", "motorola",
        "zyxel", "broadcom", "cisco", "dlink", "ubnt"
    }

    # High entropy token regex (Base64, Hex 32/64 char hashes, API keys)
    CANDIDATE_TOKEN_REGEX = re.compile(r"['\"]([A-Za-z0-9+/=_-]{16,64})['\"]")

    def __init__(self, rootfs_path: Path):
        self.rootfs_path = Path(rootfs_path).resolve()

    @staticmethod
    def calculate_string_entropy(text: str) -> float:
        """Calculates Shannon entropy for string tokens (0.0 to ~6.0 for alphanumeric)."""
        if not text:
            return 0.0
        length = len(text)
        counts = Counter(text)
        entropy = 0.0
        for count in counts.values():
            prob = count / length
            entropy -= prob * math.log2(prob)
        return round(entropy, 4)

    def scan(self) -> Dict[str, Any]:
        """Runs all static checks and aggregates findings."""
        findings: List[Dict[str, Any]] = []

        if not self.rootfs_path.is_dir():
            return {"findings": [], "summary": {"total": 0, "critical": 0, "high": 0}}

        findings.extend(self._scan_private_keys())
        findings.extend(self._scan_file_contents())
        findings.extend(self._scan_suid_binaries())
        findings.extend(self._scan_entropy_tokens())

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

                        # Audit known IoT vendor default passwords
                        for word in self.IOT_VENDOR_DEFAULTS:
                            if f"={word}" in content or f"='{word}'" in content or f'="{word}"' in content:
                                results.append({
                                    "category": "Factory Default Credential",
                                    "path": str(fpath.relative_to(self.rootfs_path)),
                                    "severity": "HIGH",
                                    "cwe": "CWE-798",
                                    "description": f"Known IoT factory default keyword found: '{word}'",
                                    "snippet": f"...{word}...",
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

    def _scan_entropy_tokens(self) -> List[Dict[str, Any]]:
        """Scans configuration and script files for high-entropy tokens (API keys, secrets)."""
        results = []
        target_exts = {".sh", ".conf", ".cfg", ".ini", ".env", ".json", ".js"}

        for root, _, files in os.walk(self.rootfs_path):
            for file in files:
                fpath = Path(root) / file
                if fpath.suffix.lower() in target_exts:
                    try:
                        if fpath.stat().st_size > 512 * 1024:
                            continue
                        content = fpath.read_text(encoding="utf-8", errors="ignore")
                        for match in self.CANDIDATE_TOKEN_REGEX.finditer(content):
                            token = match.group(1)
                            # Ignore common paths or repetitive text
                            if "/" in token or token.count("0") > len(token) // 2:
                                continue
                            ent = self.calculate_string_entropy(token)
                            # High-entropy random token threshold: > 3.8 bits per char on 20+ char string
                            if len(token) >= 20 and ent >= 3.85:
                                results.append({
                                    "category": "High-Entropy Secret / API Token",
                                    "path": str(fpath.relative_to(self.rootfs_path)),
                                    "severity": "HIGH",
                                    "cwe": "CWE-798",
                                    "description": f"High-entropy token detected (entropy: {ent}, length: {len(token)})",
                                    "snippet": f"{token[:8]}...{token[-4:]}",
                                })
                    except Exception:
                        pass
        return results
