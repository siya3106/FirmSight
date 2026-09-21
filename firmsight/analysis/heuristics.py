"""
Behavioral Traffic Heuristics and C2 Detection
Analyzes network events and flagged patterns indicative of IoT botnets or phone-home telemetry.
"""

from typing import Dict, Any, List, Optional

class TrafficHeuristicsEngine:
    """Evaluates network telemetry against common IoT botnet and backdoor signatures."""

    SUSPICIOUS_PORTS = {23, 2323, 4444, 5555, 6667, 7777, 8888, 31337}
    SUSPICIOUS_TLDS = {".tk", ".top", ".xyz", ".bid", ".club", ".duckdns.org"}
    SUSPICIOUS_KEYWORDS = ["beacon", "c2", "mirai", "payload", "cmd", "shell", "wget", "tftp"]

    @classmethod
    def evaluate_event(cls, event: Dict[str, Any]) -> Dict[str, Any]:
        """Evaluates an individual network event and returns an enriched report with severity."""
        reasons = []
        severity = "INFO"

        dst = event.get("dst", "")
        info = event.get("info", "").lower()
        proto = event.get("proto", "")

        # 1. Port anomaly check
        for port in cls.SUSPICIOUS_PORTS:
            if f":{port}" in dst or f"port {port}" in info:
                reasons.append(f"Suspicious destination port {port} (commonly associated with botnets/C2)")
                severity = "HIGH"

        # 2. DNS domain heuristics
        if proto == "DNS":
            for tld in cls.SUSPICIOUS_TLDS:
                if tld in info:
                    reasons.append(f"Suspicious TLD/DDNS provider queried: {tld}")
                    if severity != "HIGH":
                        severity = "MEDIUM"

        # 3. Keyword / payload indicators
        for kw in cls.SUSPICIOUS_KEYWORDS:
            if kw in info:
                reasons.append(f"Detected suspicious pattern keyword: '{kw}'")
                severity = "HIGH"

        # 4. Mass scanning indicators
        if "scanning" in info or "sweep" in info:
            reasons.append("Reconnaissance / scanning pattern detected")
            severity = "CRITICAL"

        is_flagged = len(reasons) > 0 or event.get("flagged", False)

        return {
            "source": event.get("src", "Unknown"),
            "destination": dst,
            "protocol": proto,
            "info": event.get("info", ""),
            "flagged": is_flagged,
            "severity": severity if is_flagged else "NORMAL",
            "reasons": reasons,
        }
