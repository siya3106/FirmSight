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

@main.command("audit")
@click.argument("firmware_path", type=click.Path(exists=True))
@click.option("--output", "-o", default="firmware_audit_report.md", help="Output path for Markdown report")
@click.option("--json-output", "-j", default=None, help="Optional output path for JSON report")
@click.option("--html-output", "-h", default=None, help="Optional output path for interactive HTML report")
def audit_firmware(firmware_path: str, output: str, json_output: Optional[str], html_output: Optional[str]):
    """Runs a complete static and dynamic audit, generating a security report."""
    from firmsight.analysis.reporter import SecurityReporter
    from firmsight.analysis.static_scanner import StaticScanner
    fw_path = Path(firmware_path)
    console.print(f"[bold cyan]Auditing firmware:[/] {fw_path}")

    # 1. Extraction
    extractor = ExtractorEngine(output_dir=Path("audit_rootfs"))
    extraction_report = extractor.extract(fw_path)

    # 2. Architecture Detection
    rootfs = Path(extraction_report["rootfs_path"])
    arch_info = ArchDetector.scan_rootfs(rootfs) or {}

    # 3. Static Vulnerability Scan
    scanner = StaticScanner(rootfs)
    static_report = scanner.scan()

    # 4. Compile Report
    reporter = SecurityReporter(target_name=fw_path.name)
    reporter.set_extraction_results(extraction_report)
    reporter.set_arch_results(arch_info)
    reporter.set_static_findings(static_report)

    md_path = Path(output)
    reporter.generate_markdown(md_path)
    console.print(f"[bold green]✓ Markdown report generated:[/] {md_path}")

    if json_output:
        j_path = Path(json_output)
        reporter.generate_json(j_path)
        console.print(f"[bold green]✓ JSON report generated:[/] {j_path}")

    if html_output:
        h_path = Path(html_output)
        reporter.generate_html(h_path)
        console.print(f"[bold green]✓ Interactive HTML report generated:[/] {h_path}")

@main.command("scan")
@click.argument("rootfs_path", type=click.Path(exists=True))
def scan_rootfs(rootfs_path: str):
    """Scans an extracted root filesystem for hardcoded secrets, backdoors, and keys."""
    from firmsight.analysis.static_scanner import StaticScanner
    p = Path(rootfs_path)
    console.print(f"[bold cyan]Scanning filesystem for vulnerabilities:[/] {p}")
    scanner = StaticScanner(p)
    results = scanner.scan()
    findings = results["findings"]

    if not findings:
        console.print("[bold green]✓ No static vulnerabilities or secrets identified.[/]")
        return

    table = Table(title=f"Static Vulnerability Findings ({len(findings)} total)", style="yellow")
    table.add_column("Severity", style="bold")
    table.add_column("CWE", style="cyan")
    table.add_column("Path", style="white")
    table.add_column("Description", style="yellow")

    for f in findings:
        sev = f.get("severity", "LOW")
        sev_colored = f"[red]{sev}[/]" if sev in ("CRITICAL", "HIGH") else f"[yellow]{sev}[/]"
        table.add_row(sev_colored, f.get("cwe", "N/A"), f.get("path", ""), f.get("description", ""))

    console.print(table)

@main.command("mock-nvram")
@click.argument("rootfs_path", type=click.Path(exists=True))
@click.option("--vendor", "-v", default="generic", type=click.Choice(["generic", "dlink", "netgear", "asus", "openwrt"]), help="Target router vendor profile")
@click.option("--override", "-o", multiple=True, help="Custom NVRAM key-value override, e.g. -o lan_ipaddr=10.0.0.1")
def mock_nvram(rootfs_path: str, vendor: str, override: List[str]):
    """Initializes virtual NVRAM key-value tables and mock binary stubs inside the rootfs."""
    from firmsight.core.nvram import NVRAMMock
    custom = {}
    for item in override:
        if "=" in item:
            k, v = item.split("=", 1)
            custom[k.strip()] = v.strip()

    nv = NVRAMMock(Path(rootfs_path))
    created = nv.initialize_mock(vendor=vendor, custom_keys=custom)
    console.print(f"[bold green]✓ Initialized {vendor.upper()} NVRAM mock table at:[/] {created}")
    if custom:
        console.print(f"Applied overrides: [cyan]{custom}[/]")

@main.command("nvram-export")
@click.argument("rootfs_path", type=click.Path(exists=True))
@click.option("--output", "-o", default="nvram_exported.json", help="Destination file path")
@click.option("--format", "-f", "fmt", default="json", type=click.Choice(["json", "env"]), help="Export format")
def nvram_export(rootfs_path: str, output: str, fmt: str):
    """Exports NVRAM table from a rootfs to JSON or .env format."""
    from firmsight.core.nvram import NVRAMMock
    nv = NVRAMMock(Path(rootfs_path))
    dest = nv.export_data(Path(output), fmt=fmt)
    console.print(f"[bold green]✓ Successfully exported NVRAM ({fmt.upper()}) to:[/] {dest}")

@main.command("nvram-import")
@click.argument("rootfs_path", type=click.Path(exists=True))
@click.argument("file_path", type=click.Path(exists=True))
def nvram_import(rootfs_path: str, file_path: str):
    """Imports and merges NVRAM key-values from a JSON or .env file."""
    from firmsight.core.nvram import NVRAMMock
    nv = NVRAMMock(Path(rootfs_path))
    merged = nv.import_data(Path(file_path))
    console.print(f"[bold green]✓ Imported {len(merged)} NVRAM keys from:[/] {file_path}")


@main.command("entropy")
@click.argument("binary_path", type=click.Path(exists=True))
@click.option("--block-size", "-b", default=1024, help="Sliding window block size in bytes")
def analyze_entropy(binary_path: str, block_size: int):
    """Calculates sliding-window Shannon entropy to identify compressed or encrypted firmware regions."""
    from firmsight.analysis.entropy import EntropyAnalyzer
    p = Path(binary_path)
    console.print(f"[bold cyan]Analyzing Shannon entropy for:[/] {p}")

    analyzer = EntropyAnalyzer(block_size=block_size)
    res = analyzer.analyze_file(p)

    console.print(f"Overall Entropy: [bold yellow]{res['overall_entropy']}[/] / 8.0 ([bold]{res['overall_classification']}[/])")
    console.print(f"Total Bytes: [bold]{res['total_bytes']}[/] | Sliding Samples: [bold]{res['curve_samples']}[/]\n")

    table = Table(title="Detected Entropy Regions", style="cyan")
    table.add_column("Start Offset", style="bold white")
    table.add_column("End Offset", style="bold white")
    table.add_column("Length", style="cyan")
    table.add_column("Avg Entropy", style="yellow")
    table.add_column("Classification", style="magenta")

    for r in res["regions"]:
        table.add_row(
            r["start_offset"],
            r["end_offset"],
            f"{r['length']} B",
            str(r["avg_entropy"]),
            r["classification"],
        )

    console.print(table)

@main.command("check-deps")
@click.argument("target_path", type=click.Path(exists=True))
def check_dependencies(target_path: str):
    """Scans an ELF binary or extracted rootfs to verify shared library (.so) dependencies."""
    from firmsight.core.dep_scanner import DependencyScanner
    p = Path(target_path)

    if p.is_file():
        scanner = DependencyScanner(rootfs_path=p.parent)
        res = scanner.inspect_binary(p)
        if not res.get("is_elf"):
            console.print("[bold red]Not a valid ELF binary.[/]")
            return

        console.print(f"[bold cyan]Binary:[/] {p.name} ({res.get('bitness')}-bit, {res.get('endianness')})")
        console.print(f"Needed Libraries: [yellow]{', '.join(res.get('needed_libraries', [])) or 'None (Statically Linked)'}[/]")
        if res.get("missing_libraries"):
            console.print(f"[bold red]Missing Dependencies:[/] {', '.join(res['missing_libraries'])}")
        else:
            console.print("[bold green]✓ All dependencies satisfied or statically linked.[/]")
    else:
        scanner = DependencyScanner(rootfs_path=p)
        res = scanner.scan_rootfs()
        console.print(f"[bold cyan]Auditing dependencies for rootfs at:[/] {p}")
        console.print(f"Binaries Audited: [bold]{res['binaries_count']}[/] | Total Missing: [bold red]{res['total_missing_dependencies']}[/]")

        table = Table(title="Shared Library Dependency Health", style="yellow")
        table.add_column("Binary", style="cyan")
        table.add_column("Needed (.so)", style="white")
        table.add_column("Missing (.so)", style="bold red")

        for b in res["binaries"]:
            needed_str = ", ".join(b.get("needed_libraries", [])) or "Static"
            missing_str = ", ".join(b.get("missing_libraries", [])) or "None"
            table.add_row(Path(b["file"]).name, needed_str, missing_str)

        console.print(table)

@main.command("header")
@click.argument("firmware_path", type=click.Path(exists=True))
def inspect_headers(firmware_path: str):
    """Parses U-Boot (uImage) and Broadcom (TRX) firmware container headers."""
    from firmsight.core.header_parser import HeaderParser
    p = Path(firmware_path)
    console.print(f"[bold cyan]Scanning firmware container headers for:[/] {p}")

    headers = HeaderParser.parse_file(p)
    if not headers:
        console.print("[bold yellow]No recognized container headers (uImage/TRX) found.[/]")
        return

    for h in headers:
        table = Table(title=f"Container Header: {h['format']} @ {h['hex_offset']}", style="green")
        table.add_column("Property", style="cyan")
        table.add_column("Value", style="bold white")

        for k, v in h.items():
            if k == "partition_offsets":
                sub_str = ", ".join([f"{part['partition']}: {part['offset']}" for part in v])
                table.add_row("Partitions", sub_str)
            else:
                table.add_row(k.replace("_", " ").title(), str(v))

        console.print(table)

if __name__ == "__main__":
    main()





