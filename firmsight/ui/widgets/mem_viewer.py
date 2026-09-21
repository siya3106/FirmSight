"""
Dynamic Memory Viewer Widget for FirmSight TUI
"""

from typing import List, Dict, Any
from textual.widgets import DataTable, Static
from textual.containers import Vertical
from rich.text import Text

class MemoryViewerPane(Vertical):
    """Displays virtual memory maps, loaded sections, and Radare2 hook information."""

    def __init__(self, **kwargs):
        super().__init__(classes="box", **kwargs)

    def compose(self):
        yield Static("🧠 Dynamic Tracer & Process Memory Maps", classes="box-title")
        table = DataTable(id="mem-table", cursor_type="row")
        yield table

    def on_mount(self):
        table = self.query_one("#mem-table", DataTable)
        table.add_columns("Start Addr", "End Addr", "Perms", "Segment / Library", "Type")

    def populate_maps(self, maps: List[Dict[str, Any]]):
        """Fills table with memory regions."""
        table = self.query_one("#mem-table", DataTable)
        table.clear()

        for m in maps:
            perm_style = "bold red" if "w" in m.get("perm", "") and "x" in m.get("perm", "") else "cyan"
            table.add_row(
                str(m.get("addr", "")),
                str(m.get("end", "")),
                Text(str(m.get("perm", "")), style=perm_style),
                str(m.get("name", "")),
                str(m.get("type", "")),
            )
