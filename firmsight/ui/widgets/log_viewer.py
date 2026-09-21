"""
Emulation Log Viewer Widget for FirmSight TUI
"""

from textual.widgets import RichLog, Static
from textual.containers import Vertical
from rich.text import Text

class LogViewerPane(Vertical):
    """Displays real-time logs and output from the QEMU emulation supervisor."""

    def __init__(self, **kwargs):
        super().__init__(classes="box", **kwargs)

    def compose(self):
        yield Static("💻 Emulation Console & Runtime Logs", classes="box-title")
        yield RichLog(id="log-viewer", highlight=True, markup=True)

    def append_line(self, line: str, level: str = "INFO"):
        """Appends a log line to the viewer with color styling."""
        log = self.query_one("#log-viewer", RichLog)
        text = Text()
        clean = line.strip()

        if "error" in clean.lower() or level == "ERROR":
            text.append(f"[ERROR] {clean}", style="bold red")
        elif "warn" in clean.lower() or level == "WARN":
            text.append(f"[WARN]  {clean}", style="bold yellow")
        elif "c2" in clean.lower() or "suspicious" in clean.lower() or "beacon" in clean.lower():
            text.append(f"[ALERT] {clean}", style="bold magenta")
        elif "[qemu" in clean.lower():
            text.append(f"[QEMU]  {clean}", style="cyan")
        else:
            text.append(f"[INFO]  {clean}", style="green")

        log.write(text)

    def clear(self):
        """Clears all logs."""
        log = self.query_one("#log-viewer", RichLog)
        log.clear()
