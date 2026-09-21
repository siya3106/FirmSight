"""
Network Activity Table Widget for FirmSight TUI
"""

from typing import Dict, Any
from textual.widgets import DataTable, Static
from textual.containers import Vertical
from rich.text import Text

class NetworkTablePane(Vertical):
    """Displays captured network traffic, destination addresses, and heuristics flags."""

    def __init__(self, **kwargs):
        super().__init__(classes="box", **kwargs)

    def compose(self):
        yield Static("🌐 Network Isolation & Traffic Interceptor", classes="box-title")
        table = DataTable(id="net-table", cursor_type="row")
        yield table

    def on_mount(self):
        table = self.query_one("#net-table", DataTable)
        table.add_columns("Time", "Source", "Destination", "Proto", "Severity", "Details")

    def add_packet_event(self, event: Dict[str, Any]):
        """Inserts a new network packet or security telemetry record into the table."""
        table = self.query_one("#net-table", DataTable)

        severity = event.get("severity", "NORMAL")
        flagged = event.get("flagged", False)

        if severity == "CRITICAL":
            sev_text = Text(f"🔴 {severity}", style="bold red")
        elif severity == "HIGH":
            sev_text = Text(f"🟠 {severity}", style="bold orange1")
        elif severity == "MEDIUM":
            sev_text = Text(f"🟡 {severity}", style="bold yellow")
        elif flagged:
            sev_text = Text("⚠ FLAGGED", style="bold yellow")
        else:
            sev_text = Text("🟢 NORMAL", style="green")

        import datetime
        now_str = datetime.datetime.now().strftime("%H:%M:%S")

        table.add_row(
            now_str,
            str(event.get("src", event.get("source", "N/A"))),
            str(event.get("dst", event.get("destination", "N/A"))),
            str(event.get("proto", event.get("protocol", "TCP"))),
            sev_text,
            str(event.get("info", "")),
        )
