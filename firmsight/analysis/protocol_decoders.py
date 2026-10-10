"""
IoT Discovery Protocol Decoders (SSDP, UPnP, mDNS)
Extracts service announcements, device models, UUIDs, and network beacons from UDP multicast payloads.
"""

import re
from typing import Dict, Any, Optional

class ProtocolDecoders:
    """Decodes common IoT discovery and advertising protocols."""

    @staticmethod
    def decode_ssdp(payload: bytes) -> Optional[Dict[str, Any]]:
        """Parses Simple Service Discovery Protocol (SSDP / UPnP M-SEARCH / NOTIFY) requests."""
        try:
            text = payload.decode("ascii", errors="ignore")
            if "HTTP/1.1" not in text and "NOTIFY" not in text and "M-SEARCH" not in text:
                return None

            headers = {}
            for line in text.splitlines():
                if ":" in line:
                    k, v = line.split(":", 1)
                    headers[k.strip().upper()] = v.strip()

            return {
                "protocol": "SSDP/UPnP",
                "method": "M-SEARCH" if "M-SEARCH" in text else ("NOTIFY" if "NOTIFY" in text else "RESPONSE"),
                "st": headers.get("ST", headers.get("NT", "")),
                "usn": headers.get("USN", ""),
                "location": headers.get("LOCATION", ""),
                "server": headers.get("SERVER", ""),
            }
        except Exception:
            return None

    @staticmethod
    def decode_http_cgi(payload: bytes) -> Optional[Dict[str, Any]]:
        """Parses HTTP requests targeting router administrative CGI endpoints."""
        try:
            text = payload.decode("ascii", errors="ignore")
            first_line = text.splitlines()[0] if text else ""
            match = re.match(r"(GET|POST|HEAD|PUT)\s+([^\s]+)\s+HTTP", first_line)
            if not match:
                return None

            method, path = match.group(1), match.group(2)
            is_cgi = ".cgi" in path or "/cgi-bin/" in path or "apply.cgi" in path
            is_auth_endpoint = any(ep in path.lower() for ep in ["login", "auth", "session", "password", "setup"])

            return {
                "protocol": "HTTP",
                "method": method,
                "path": path,
                "is_cgi": is_cgi,
                "is_auth_endpoint": is_auth_endpoint,
            }
        except Exception:
            return None
