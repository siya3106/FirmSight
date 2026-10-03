"""
NVRAM (Non-Volatile RAM) Interceptor and Mocking Engine
Solves the common firmware emulation bottleneck where IoT daemons crash due to missing NVRAM keys.
Supports multi-vendor profiles (D-Link, Netgear, ASUS, OpenWrt), import/export, and mock binary stubs.
"""

import json
from pathlib import Path
from typing import Dict, Any, Optional, List

class NVRAMMock:
    """Manages virtualized NVRAM key-value stores for IoT router daemons."""

    VENDOR_PROFILES = {
        "generic": {
            "lan_ipaddr": "192.168.1.1",
            "lan_netmask": "255.255.255.0",
            "lan_gateway": "192.168.1.1",
            "wan_ipaddr": "198.51.100.50",
            "wan_netmask": "255.255.255.0",
            "wan_gateway": "198.51.100.1",
            "dns_servers": "8.8.8.8 8.8.4.4",
            "http_username": "admin",
            "http_passwd": "password",
            "http_port": "80",
            "https_port": "443",
            "wl0_ssid": "FirmSight-Sandbox-AP",
            "wl0_wpa_psk": "defaultpassword123",
            "boardtype": "bcm947xx",
            "model_name": "Generic-Router",
            "firmware_version": "v1.0.0-build2026",
        },
        "dlink": {
            "lan_ipaddr": "192.168.0.1",
            "lan_netmask": "255.255.255.0",
            "http_username": "admin",
            "http_passwd": "",
            "http_port": "80",
            "def_wireless_ssid": "dlink-router",
            "wps_pin": "12345670",
            "hw_ver": "A1",
            "model_name": "DIR-850L",
            "factory_default": "1",
            "wlan0_security": "wpa2_aes",
        },
        "netgear": {
            "lan_ipaddr": "192.168.1.1",
            "lan_netmask": "255.255.255.0",
            "http_username": "admin",
            "http_passwd": "password",
            "board_id": "U12H270T00_NETGEAR",
            "region": "North America",
            "ntp_server": "time.nist.gov",
            "wl_ssid": "NETGEAR_5G",
            "wl_wpa2_psk": "secretnetgearpass",
            "model_name": "R7000",
        },
        "asus": {
            "lan_ipaddr": "192.168.1.1",
            "lan_netmask": "255.255.255.0",
            "http_username": "admin",
            "http_passwd": "admin",
            "productid": "RT-AC68U",
            "nvram_version": "1.0",
            "apps_state_switch": "1",
            "wl0_ssid": "ASUS_Router",
            "wl0_wpa_psk": "asuspassword",
        },
        "openwrt": {
            "network_lan_ipaddr": "192.168.1.1",
            "network_lan_netmask": "255.255.255.0",
            "system_hostname": "OpenWrt",
            "system_timezone": "UTC",
            "dropbear_port": "22",
            "uhttpd_listen_http": "0.0.0.0:80",
        },
    }

    def __init__(self, rootfs_path: Path):
        self.rootfs_path = Path(rootfs_path).resolve()
        self.nvram_file = self.rootfs_path / "etc" / "firmsight_nvram.json"

    def initialize_mock(self, vendor: str = "generic", custom_keys: Optional[Dict[str, str]] = None) -> Path:
        """Injects vendor profile and custom NVRAM entries into the target rootfs."""
        profile = self.VENDOR_PROFILES.get(vendor.lower(), self.VENDOR_PROFILES["generic"]).copy()
        if custom_keys:
            profile.update(custom_keys)

        self.nvram_file.parent.mkdir(parents=True, exist_ok=True)
        with open(self.nvram_file, "w", encoding="utf-8") as f:
            json.dump(profile, f, indent=2)

        # Install mock nvram shell stub in rootfs
        self.install_mock_binary()

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
        return self.VENDOR_PROFILES["generic"].get(key, default)

    def set(self, key: str, value: str) -> None:
        """Updates an NVRAM key."""
        table = self.VENDOR_PROFILES["generic"].copy()
        if self.nvram_file.is_file():
            try:
                with open(self.nvram_file, "r", encoding="utf-8") as f:
                    table.update(json.load(f))
            except Exception:
                pass
        table[key] = value
        with open(self.nvram_file, "w", encoding="utf-8") as f:
            json.dump(table, f, indent=2)

    def export_data(self, output_path: Path, fmt: str = "json") -> Path:
        """Exports NVRAM dictionary to JSON or .env format."""
        table = self.get_all()
        output_path = Path(output_path).resolve()
        output_path.parent.mkdir(parents=True, exist_ok=True)

        if fmt.lower() == "env":
            lines = [f"{k}={v}" for k, v in table.items()]
            output_path.write_text("\n".join(lines), encoding="utf-8")
        else:
            output_path.write_text(json.dumps(table, indent=2), encoding="utf-8")

        return output_path

    def import_data(self, input_path: Path) -> Dict[str, str]:
        """Imports NVRAM key-values from a JSON or .env file."""
        input_path = Path(input_path).resolve()
        if not input_path.is_file():
            raise FileNotFoundError(f"File not found: {input_path}")

        raw_text = input_path.read_text(encoding="utf-8").strip()
        imported = {}

        if raw_text.startswith("{"):
            imported = json.loads(raw_text)
        else:
            for line in raw_text.splitlines():
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, v = line.split("=", 1)
                    imported[k.strip()] = v.strip()

        # Merge with existing
        existing = self.get_all()
        existing.update(imported)

        self.nvram_file.parent.mkdir(parents=True, exist_ok=True)
        with open(self.nvram_file, "w", encoding="utf-8") as f:
            json.dump(existing, f, indent=2)

        return existing

    def get_all(self) -> Dict[str, str]:
        """Returns all currently configured NVRAM pairs."""
        if self.nvram_file.is_file():
            try:
                with open(self.nvram_file, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                pass
        return self.VENDOR_PROFILES["generic"].copy()

    def install_mock_binary(self) -> Optional[Path]:
        """Installs a /usr/sbin/nvram mock script inside rootfs to intercept calls from daemons."""
        bin_dir = self.rootfs_path / "usr" / "sbin"
        bin_dir.mkdir(parents=True, exist_ok=True)
        stub_file = bin_dir / "nvram"

        script = (
            "#!/bin/sh\n"
            "# FirmSight Virtual NVRAM Interceptor\n"
            "NV_JSON=/etc/firmsight_nvram.json\n"
            'if [ "$1" = "get" ]; then\n'
            '    python3 -c "import json; data=json.load(open(\'$NV_JSON\')); print(data.get(\'$2\', \'\'))" 2>/dev/null || echo ""\n'
            'elif [ "$1" = "set" ]; then\n'
            '    python3 -c "import json; data=json.load(open(\'$NV_JSON\')); data[\'$2\']=\'$3\'; json.dump(data, open(\'$NV_JSON\', \'w\'))" 2>/dev/null\n'
            'elif [ "$1" = "show" ]; then\n'
            '    python3 -c "import json; [print(f\'{k}={v}\') for k, v in json.load(open(\'$NV_JSON\')).items()]" 2>/dev/null\n'
            "fi\n"
        )

        try:
            stub_file.write_text(script, encoding="utf-8")
            return stub_file
        except Exception:
            return None
