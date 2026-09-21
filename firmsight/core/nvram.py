"""
NVRAM (Non-Volatile RAM) Interceptor and Mocking Engine
Solves the common firmware emulation bottleneck where IoT daemons crash due to missing NVRAM keys.
"""

import json
from pathlib import Path
from typing import Dict, Any, Optional

class NVRAMMock:
    """Manages virtualized NVRAM key-value stores for IoT router daemons."""

    DEFAULT_NVRAM_TABLE = {
        # Network configurations
        "lan_ipaddr": "192.168.1.1",
        "lan_netmask": "255.255.255.0",
        "lan_gateway": "192.168.1.1",
        "wan_ipaddr": "198.51.100.50",
        "wan_netmask": "255.255.255.0",
        "wan_gateway": "198.51.100.1",
        "dns_servers": "8.8.8.8 8.8.4.4",
        # Administrative accounts
        "http_username": "admin",
        "http_passwd": "password",
        "http_port": "80",
        "https_port": "443",
        # Wireless configurations
        "wl0_ssid": "FirmSight-Sandbox-AP",
        "wl0_wpa_psk": "defaultpassword123",
        # Hardware identifiers
        "boardtype": "bcm947xx",
        "model_name": "DIR-850L",
        "firmware_version": "v1.0.0-build2026",
    }

    def __init__(self, rootfs_path: Path):
        self.rootfs_path = Path(rootfs_path).resolve()
        self.nvram_file = self.rootfs_path / "etc" / "firmsight_nvram.json"

    def initialize_mock(self, custom_keys: Optional[Dict[str, str]] = None) -> Path:
        """Injects default and custom NVRAM entries into the target rootfs."""
        table = self.DEFAULT_NVRAM_TABLE.copy()
        if custom_keys:
            table.update(custom_keys)

        self.nvram_file.parent.mkdir(parents=True, exist_ok=True)
        with open(self.nvram_file, "w", encoding="utf-8") as f:
            json.dump(table, f, indent=2)

        return self.nvram_file

    def get(self, key: str, default: Optional[str] = None) -> Optional[str]:
        """Retrieves an NVRAM key."""
        if self.nvram_file.is_file():
            try:
                with open(self.nvram_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    return data.get(key, default)
            except Exception:
                pass
        return self.DEFAULT_NVRAM_TABLE.get(key, default)

    def set(self, key: str, value: str) -> None:
        """Updates an NVRAM key."""
        table = self.DEFAULT_NVRAM_TABLE.copy()
        if self.nvram_file.is_file():
            try:
                with open(self.nvram_file, "r", encoding="utf-8") as f:
                    table.update(json.load(f))
            except Exception:
                pass
        table[key] = value
        with open(self.nvram_file, "w", encoding="utf-8") as f:
            json.dump(table, f, indent=2)
