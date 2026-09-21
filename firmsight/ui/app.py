"""
FirmSight Textual Application Main Dashboard
"""

import asyncio
from pathlib import Path
from typing import Optional

from textual.app import App, ComposeResult
from textual.containers import Container, Horizontal, Vertical
from textual.widgets import Header, Footer

from firmsight.ui.widgets.fs_tree import FilesystemTreePane
from firmsight.ui.widgets.log_viewer import LogViewerPane
from firmsight.ui.widgets.net_table import NetworkTablePane
from firmsight.ui.widgets.mem_viewer import MemoryViewerPane

from firmsight.core.detector import ArchDetector
from firmsight.core.emulator import QEMUEmulator
from firmsight.core.network import NetworkManager
from firmsight.core.tracer import DynamicTracer
from firmsight.analysis.heuristics import TrafficHeuristicsEngine

class FirmSightApp(App):
    """Main Textual interactive terminal dashboard for firmware dynamic analysis."""

    CSS_PATH = "styles.tcss"
    TITLE = "FirmSight :: IoT Firmware Dynamic Analysis & Emulation Pipeline"
    SUB_TITLE = "[q: Quit | e: Start/Stop Emulation | t: Trace Memory | c: Clear Logs]"

    BINDINGS = [
        ("q", "quit", "Quit"),
        ("e", "toggle_emulation", "Start/Stop Emulation"),
        ("t", "trigger_trace", "Trace Memory"),
        ("c", "clear_logs", "Clear Logs"),
    ]

    def __init__(self, rootfs_path: Optional[Path] = None, firmware_path: Optional[Path] = None, **kwargs):
        super().__init__(**kwargs)
        self.rootfs_path = Path(rootfs_path).resolve() if rootfs_path else Path.cwd()
        self.firmware_path = Path(firmware_path).resolve() if firmware_path else None

        # Core engine controllers
        self.detector = ArchDetector()
        self.emulator: Optional[QEMUEmulator] = None
        self.network_mgr: Optional[NetworkManager] = None
        self.tracer: Optional[DynamicTracer] = None
        self.detected_arch = None

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Container(id="main-container"):
            yield FilesystemTreePane(root_path=self.rootfs_path)
            yield LogViewerPane(id="log-pane")
            yield NetworkTablePane(id="net-pane")
            yield MemoryViewerPane(id="mem-pane")
        yield Footer()

    async def on_mount(self) -> None:
        """Initializes detectors and subsystems upon UI mounting."""
        log_pane = self.query_one("#log-pane", LogViewerPane)
        log_pane.append_line("FirmSight dynamic analysis engine initialized.")

        # 1. Architecture scan on target rootfs
        if self.rootfs_path.is_dir():
            log_pane.append_line(f"Scanning target filesystem at: {self.rootfs_path}")
            arch_info = self.detector.scan_rootfs(self.rootfs_path)
            if arch_info:
                self.detected_arch = arch_info
                log_pane.append_line(
                    f"Identified architecture: {arch_info['arch']} ({arch_info['bitness']}-bit, {arch_info['endianness']}-endian)"
                )
                log_pane.append_line(f"Selected QEMU target: {arch_info['qemu_target']}")
            else:
                log_pane.append_line("No foreign ELF binaries identified. Defaulting to ARM target.")

        # 2. Setup Network Supervisor with Heuristics
        self.network_mgr = NetworkManager(
            on_packet_event=self._handle_network_packet
        )
        self.network_mgr.setup_bridge()
        self.network_mgr.start_capture()
        log_pane.append_line("Virtual network bridge initialized and packet interceptor active.")

        # 3. Setup QEMU Emulator
        qemu_target = self.detected_arch.get("qemu_target", "qemu-arm-static") if self.detected_arch else "qemu-arm-static"
        self.emulator = QEMUEmulator(
            rootfs_path=self.rootfs_path,
            qemu_binary=qemu_target,
            on_stdout=lambda line: self.call_from_thread(self._handle_emulator_output, line, "INFO"),
            on_stderr=lambda line: self.call_from_thread(self._handle_emulator_output, line, "ERROR"),
        )

        # 4. Initialize Memory Tracer
        self.tracer = DynamicTracer()
        self.action_trigger_trace()

    def _handle_emulator_output(self, line: str, level: str):
        """Dispatches emulator output to the UI log pane."""
        try:
            log_pane = self.query_one("#log-pane", LogViewerPane)
            log_pane.append_line(line, level=level)
        except Exception:
            pass

    def _handle_network_packet(self, raw_event: dict):
        """Analyzes packet with heuristics and updates UI."""
        enriched = TrafficHeuristicsEngine.evaluate_event(raw_event)
        self.call_from_thread(self._post_packet_update, enriched)

    def _post_packet_update(self, enriched: dict):
        try:
            net_pane = self.query_one("#net-pane", NetworkTablePane)
            net_pane.add_packet_event(enriched)
            if enriched.get("flagged"):
                log_pane = self.query_one("#log-pane", LogViewerPane)
                log_pane.append_line(
                    f"Heuristic Flag: Outbound connection to {enriched['destination']} ({enriched['severity']})",
                    level="WARN"
                )
        except Exception:
            pass

    def action_toggle_emulation(self) -> None:
        """Starts or stops the QEMU emulation supervisor."""
        log_pane = self.query_one("#log-pane", LogViewerPane)
        if not self.emulator:
            return

        if self.emulator.is_running:
            self.emulator.stop()
            log_pane.append_line("QEMU Emulation terminated.", level="WARN")
        else:
            log_pane.append_line("Starting QEMU emulation environment...")
            self.emulator.start_user_mode(target_binary="/usr/sbin/uhttpd")
            log_pane.append_line("QEMU process active and sandbox engaged.")

    def action_trigger_trace(self) -> None:
        """Dumps memory regions into the Memory Viewer pane."""
        if self.tracer:
            maps = self.tracer.get_memory_maps()
            mem_pane = self.query_one("#mem-pane", MemoryViewerPane)
            mem_pane.populate_maps(maps)

    def action_clear_logs(self) -> None:
        """Clears emulation logs."""
        log_pane = self.query_one("#log-pane", LogViewerPane)
        log_pane.clear()

    async def action_quit(self) -> None:
        """Performs clean shutdown on exit."""
        if self.emulator:
            self.emulator.stop()
        if self.network_mgr:
            self.network_mgr.teardown()
        await super().action_quit()

def run_tui(rootfs_path: Optional[Path] = None, firmware_path: Optional[Path] = None):
    """Launcher entry point for Textual UI."""
    app = FirmSightApp(rootfs_path=rootfs_path, firmware_path=firmware_path)
    app.run()
