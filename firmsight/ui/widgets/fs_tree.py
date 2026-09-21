"""
Filesystem Explorer Widget for FirmSight TUI
"""

from pathlib import Path
from typing import Optional
from textual.widgets import DirectoryTree, Static
from textual.containers import Vertical
from rich.text import Text

class HighlightedDirectoryTree(DirectoryTree):
    """Custom DirectoryTree that highlights sensitive firmware files and binaries."""

    SENSITIVE_NAMES = {"passwd", "shadow", "inittab", "uhttpd", "httpd", "boa", "busybox", "config"}

    def render_label(self, node, base_style, group_style):
        name = node.data.path.name.lower()
        if name in self.SENSITIVE_NAMES:
            label = Text(f"⚠ {node.data.path.name}", style="bold yellow")
            return label
        return super().render_label(node, base_style, group_style)

class FilesystemTreePane(Vertical):
    """Filesystem explorer pane containing header and tree browser."""

    def __init__(self, root_path: Optional[Path] = None, **kwargs):
        super().__init__(classes="box", id="fs-container", **kwargs)
        self.root_path = Path(root_path) if root_path and Path(root_path).exists() else Path.cwd()

    def compose(self):
        yield Static("📂 Extracted Filesystem Tree", classes="box-title")
        yield HighlightedDirectoryTree(str(self.root_path), id="tree-view")

    def update_root(self, new_root: Path):
        """Updates the tree to point to a freshly extracted firmware directory."""
        self.root_path = Path(new_root)
        tree = self.query_one("#tree-view", HighlightedDirectoryTree)
        tree.path = str(self.root_path)
        tree.reload()
