"""
FirmSight Command-Line Interface
"""

import sys
import click
from pathlib import Path
from rich.console import Console
from rich.table import Table

from firmsight.core.extractor import ExtractorEngine
from firmsight.core.detector import ArchDetector
from firmsight.utils.mock_firmware import create_mock_firmware
from firmsight.ui.app import run_tui

console = Console()

@click.group()
@click.version_option(version="0.1.0", prog_name="firmsight")
def main():
    """FirmSight: Automated IoT Firmware Dynamic Analysis and Emulation Platform."""
    pass

@main.command("make-mock")
@click.option("--output", "-o", default="mock_firmware.bin", help="Output firmware path")
def make_mock(output: str):
    """Generates a synthetic vulnerable firmware binary for testing."""
    target = Path(output)
    console.print(f"[bold cyan]Generating mock ARM IoT router firmware at:[/] {target}")
    created = create_mock_firmware(target)
    console.print(f"[bold green]✓ Successfully generated mock firmware binary:[/] {created} ({created.stat().st_size} bytes)")
    console.print("[dim]Run 'firmsight extract <firmware>' to test filesystem unpacking.[/]")

@main.command("extract")
@click.argument("firmware_path", type=click.Path(exists=True))
@click.option("--output", "-o", default="extracted_rootfs", help="Target extraction directory")
def extract(firmware_path: str, output: str):
    """Unpacks firmware image and carves root filesystem."""
    console.print(f"[bold cyan]Initiating extraction on:[/] {firmware_path}")
    extractor = ExtractorEngine(output_dir=Path(output))
    try:
        report = extractor.extract(Path(firmware_path))
        console.print(f"[bold green]✓ Extraction successful![/] Method: [bold yellow]{report['method']}[/]")
        console.print(f"Files extracted: [bold cyan]{report['file_count']}[/] ({report['total_bytes']} bytes)")
        console.print(f"Rootfs located at: [bold]{report['rootfs_path']}[/]")

        if report.get("sensitive_files"):
            table = Table(title="Sensitive Files & Backdoor Audits", style="red")
            table.add_column("Path", style="cyan")
            table.add_column("Description", style="yellow")
            table.add_column("Size", style="magenta")
            for sf in report["sensitive_files"]:
                table.add_row(sf["path"], sf["description"], str(sf.get("size_bytes", "DIR")))
            console.print(table)
    except Exception as e:
        console.print(f"[bold red]Extraction failed:[/] {e}")
        sys.exit(1)

@main.command("detect")
@click.argument("path", type=click.Path(exists=True))
def detect(path: str):
    """Inspects an ELF binary or extracted rootfs to detect architecture and endianness."""
    p = Path(path)
    if p.is_file():
        info = ArchDetector.inspect_file(p)
    else:
        info = ArchDetector.scan_rootfs(p)

    if not info:
        console.print("[bold red]No valid ELF or supported architecture found.[/]")
        sys.exit(1)

    table = Table(title="Architecture Detection Result", style="green")
    table.add_column("Property", style="cyan")
    table.add_column("Value", style="bold white")

    table.add_row("Architecture", str(info.get("arch")))
    table.add_row("Bitness", f"{info.get('bitness')}-bit")
    table.add_row("Endianness", str(info.get("endianness")))
    table.add_row("QEMU Target", str(info.get("qemu_target")))
    table.add_row("Sample Binary", str(info.get("file_path")))
    console.print(table)

@main.command("tui")
@click.option("--firmware", "-f", default=None, help="Path to raw firmware binary to extract first")
@click.option("--rootfs", "-r", default=None, help="Path to already extracted rootfs directory")
def launch_tui(firmware: str, rootfs: str):
    """Launches the interactive Textual Terminal Dashboard."""
    root_dir = Path(rootfs) if rootfs else None

    # If firmware provided, extract it first into a working directory
    if firmware and not root_dir:
        fw_path = Path(firmware)
        extract_dir = Path("extracted_rootfs")
        console.print(f"[dim]Auto-extracting {fw_path} before launching TUI...[/]")
        extractor = ExtractorEngine(output_dir=extract_dir)
        report = extractor.extract(fw_path)
        root_dir = Path(report["rootfs_path"])

    if not root_dir or not root_dir.exists():
        # Fallback to current working directory
        root_dir = Path.cwd()

    run_tui(rootfs_path=root_dir, firmware_path=Path(firmware) if firmware else None)

if __name__ == "__main__":
    main()
