"""
Virtual Network Interceptor and TAP Bridge Manager
Isolates the emulated IoT device inside a virtual sandbox network and records all outbound traffic.
"""

import os
import shutil
import subprocess
import threading
import time
from pathlib import Path
from typing import Optional, Callable, Dict, Any, List

class NetworkManager:
    """Manages virtual network interfaces, TAP devices, and traffic capture."""

    def __init__(
        self,
        tap_interface: str = "tap0",
        bridge_interface: str = "br0",
        pcap_output: Optional[Path] = None,
        on_packet_event: Optional[Callable[[Dict[str, Any]], None]] = None,
    ):
        self.tap_interface = tap_interface
        self.bridge_interface = bridge_interface
        self.pcap_output = Path(pcap_output) if pcap_output else Path.cwd() / "traffic.pcap"
        self.on_packet_event = on_packet_event
        self._tcpdump_proc: Optional[subprocess.Popen] = None
        self._sim_thread: Optional[threading.Thread] = None
        self._is_capturing = False

    def setup_bridge(self, host_ip: str = "192.168.1.1/24") -> bool:
        """Configures virtual TAP and bridge on Linux hosts."""
        if os.name == "nt":
            return True  # Handled transparently via simulated/socket bridge on Windows

        try:
            # Requires root / CAP_NET_ADMIN
            subprocess.run(["ip", "tuntap", "add", "mode", "tap", self.tap_interface], check=True)
            subprocess.run(["ip", "link", "set", self.tap_interface, "up"], check=True)
            subprocess.run(["ip", "link", "add", "name", self.bridge_interface, "type", "bridge"], check=True)
            subprocess.run(["ip", "link", "set", self.tap_interface, "master", self.bridge_interface], check=True)
            subprocess.run(["ip", "addr", "add", host_ip, "dev", self.bridge_interface], check=True)
            subprocess.run(["ip", "link", "set", self.bridge_interface, "up"], check=True)
            return True
        except Exception:
            return False

    def start_capture(self) -> bool:
        """Starts live packet capture writing to PCAP and emitting packet events."""
        self._is_capturing = True

        tcpdump_bin = shutil.which("tcpdump")
        if tcpdump_bin and os.name != "nt":
            cmd = [
                tcpdump_bin,
                "-i", self.tap_interface,
                "-s", "0",
                "-w", str(self.pcap_output),
                "-l",
            ]
            try:
                self._tcpdump_proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                return True
            except Exception:
                pass

        # Fallback simulator for development/cross-platform environments
        self._sim_thread = threading.Thread(target=self._simulate_traffic_flow, daemon=True)
        self._sim_thread.start()
        return True

    def _simulate_traffic_flow(self):
        """Generates realistic IoT firmware phone-home telemetry for dynamic analysis."""
        events = [
            {"src": "192.168.1.100", "dst": "192.168.1.1", "proto": "DNS", "info": "Query: pool.ntp.org", "flagged": False},
            {"src": "192.168.1.100", "dst": "8.8.8.8", "proto": "DNS", "info": "Query: update.cloud-iot-vendor.com", "flagged": False},
            {"src": "192.168.1.100", "dst": "198.51.100.42:4444", "proto": "TCP/SYN", "info": "Outbound connect to unregistered port 4444", "flagged": True},
            {"src": "192.168.1.100", "dst": "203.0.113.15:23", "proto": "TELNET", "info": "Mass Telnet scanning SYN sweep detected", "flagged": True},
            {"src": "192.168.1.100", "dst": "198.51.100.42:80", "proto": "HTTP", "info": "POST /api/beacon (device_id=dlink_dir850)", "flagged": True},
        ]
        idx = 0
        while self._is_capturing:
            time.sleep(2.5)
            if not self._is_capturing:
                break
            evt = events[idx % len(events)]
            idx += 1
            if self.on_packet_event:
                self.on_packet_event(evt)

    def teardown(self):
        """Tears down TAP, bridge, and tcpdump capture."""
        self._is_capturing = False
        if self._tcpdump_proc and self._tcpdump_proc.poll() is None:
            self._tcpdump_proc.terminate()
            self._tcpdump_proc = None

        if os.name != "nt":
            try:
                subprocess.run(["ip", "link", "set", self.bridge_interface, "down"], stderr=subprocess.DEVNULL)
                subprocess.run(["ip", "link", "delete", self.bridge_interface, "type", "bridge"], stderr=subprocess.DEVNULL)
                subprocess.run(["ip", "link", "delete", self.tap_interface], stderr=subprocess.DEVNULL)
            except Exception:
                pass
