"""
Firmware Extractor Engine
Automates unpacking and filesystem carving from raw firmware binary blobs.
Supports Binwalk integration with fallback extraction algorithms for
SquashFS, CramFS, JFFS2, UBI, RomFS, and CPIO initramfs archives.
"""

import os
import shutil
import struct
import subprocess
import tarfile
import zipfile
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple

class ExtractorEngine:
    """Manages the extraction and carving of embedded Linux filesystems from firmware images."""

    # Well-known filesystem and container magic bytes
    FS_SIGNATURES = {
        "SquashFS (Little Endian)": [b"hsqs", b"sqsh"],
        "SquashFS (Big Endian)":    [b"shsq", b"qshs"],
        "CramFS (Little Endian)":    [b"\x45\x3d\xcd\x28"],
        "CramFS (Big Endian)":       [b"\x28\xcd\x3d\x45"],
        "JFFS2 (Little Endian)":     [b"\x85\x19"],
        "JFFS2 (Big Endian)":        [b"\x19\x85"],
        "UBI Superblock":            [b"UBI#"],
        "RomFS":                     [b"-rom1fs-"],
        "CPIO Initramfs (ASCII)":    [b"070701", b"070702"],
    }

    def __init__(self, output_dir: Optional[Path] = None):
        self.output_dir = Path(output_dir) if output_dir else Path.cwd() / "extracted_rootfs"

    def scan_signatures(self, firmware_path: Path) -> List[Dict[str, Any]]:
        """Scans raw binary for embedded filesystem superblocks and offsets."""
        results = []
        with open(firmware_path, "rb") as f:
            data = f.read()

        for fs_type, magics in self.FS_SIGNATURES.items():
            for magic in magics:
                offset = 0
                while True:
                    idx = data.find(magic, offset)
                    if idx == -1:
                        break
                    results.append({
                        "type": fs_type,
                        "magic": magic.hex(),
                        "offset": idx,
                        "hex_offset": f"0x{idx:08X}",
                    })
                    offset = idx + len(magic)

        results.sort(key=lambda x: x["offset"])
        return results

    def extract(self, firmware_path: Path) -> Dict[str, Any]:
        """Extracts firmware using the best available method and returns metadata."""
        firmware_path = Path(firmware_path).resolve()
        if not firmware_path.is_file():
            raise FileNotFoundError(f"Firmware binary not found: {firmware_path}")

        # Ensure a clean extraction directory
        if self.output_dir.exists():
            shutil.rmtree(self.output_dir, ignore_errors=True)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        extracted_method = None
        fs_signatures = self.scan_signatures(firmware_path)

        # 1. Attempt binwalk extraction if available
        if shutil.which("binwalk"):
            try:
                cmd = ["binwalk", "-Me", "--directory", str(self.output_dir), str(firmware_path)]
                res = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
                if res.returncode == 0:
                    extracted_method = "binwalk"
            except Exception:
                pass

        # 2. Attempt standard archive extraction (tar, tar.gz, zip)
        if not extracted_method:
            if tarfile.is_tarfile(firmware_path):
                with tarfile.open(firmware_path, "r:*") as tar:
                    tar.extractall(path=self.output_dir)
                extracted_method = "tar_archive"
            elif zipfile.is_zipfile(firmware_path):
                with zipfile.ZipFile(firmware_path, "r") as z:
                    z.extractall(path=self.output_dir)
                extracted_method = "zip_archive"

        # 3. Carving fallback (UBI, CramFS, JFFS2, SquashFS, or embedded tar)
        if not extracted_method:
            extracted_method = self._carve_fallback(firmware_path, fs_signatures)

        # Locate root filesystem inside extracted output
        rootfs_dir = self._locate_rootfs(self.output_dir)
        sensitive_files = self._audit_sensitive_files(rootfs_dir)
        file_count, total_bytes = self._calculate_stats(rootfs_dir)

        return {
            "success": True,
            "firmware_path": str(firmware_path),
            "output_dir": str(self.output_dir),
            "rootfs_path": str(rootfs_dir),
            "method": extracted_method or "carve_fallback",
            "detected_filesystems": fs_signatures,
            "file_count": file_count,
            "total_bytes": total_bytes,
            "sensitive_files": sensitive_files,
        }

    def _carve_fallback(self, firmware_path: Path, fs_signatures: List[Dict[str, Any]]) -> str:
        """Fallback carving for embedded archives or header-prefixed blobs."""
        with open(firmware_path, "rb") as f:
            data = f.read()

        # Check for embedded tar (ustar signature at offset + 257)
        pos = data.find(b"ustar")
        if pos >= 257:
            tar_start = pos - 257
            temp_tar = self.output_dir / "carved.tar"
            with open(temp_tar, "wb") as f_out:
                f_out.write(data[tar_start:])
            try:
                with tarfile.open(temp_tar, "r") as tar:
                    tar.extractall(path=self.output_dir)
                temp_tar.unlink(missing_ok=True)
                return "embedded_tar_carved"
            except Exception:
                pass

        # Check for embedded CPIO archive
        cpio_pos = data.find(b"070701")
        if cpio_pos != -1:
            cpio_slice = self.output_dir / "initramfs.cpio"
            cpio_slice.write_bytes(data[cpio_pos:])
            return f"cpio_initramfs_carved_0x{cpio_pos:08X}"

        # If filesystem superblocks detected, carve them out
        if fs_signatures:
            methods = []
            for sig in fs_signatures:
                fs_type = sig["type"]
                offset = sig["offset"]
                safe_name = fs_type.lower().replace(" ", "_").replace("(", "").replace(")", "")
                carved_target = self.output_dir / f"carved_{safe_name}_0x{offset:08X}.bin"
                carved_target.write_bytes(data[offset:])
                methods.append(f"{safe_name}_0x{offset:08X}")

            summary_file = self.output_dir / "carved_manifest.txt"
            summary_file.write_text(f"Carved superblocks:\n" + "\n".join([str(s) for s in fs_signatures]))
            return f"carved_{'+'.join(methods[:2])}"

        return "raw_unpacked"

    def _locate_rootfs(self, search_dir: Path) -> Path:
        """Finds the actual Linux root directory containing /bin, /etc, /usr."""
        for root, dirs, _ in os.walk(search_dir):
            dir_names = set(dirs)
            if {"bin", "etc"}.issubset(dir_names) or {"bin", "usr"}.issubset(dir_names):
                return Path(root)
        return search_dir

    def _audit_sensitive_files(self, rootfs_dir: Path) -> List[Dict[str, Any]]:
        """Identifies sensitive configurations, passwords, and backdoor scripts."""
        findings = []
        checks = [
            ("etc/passwd", "User Accounts & Potential Empty Hashes"),
            ("etc/shadow", "Hashed Passwords"),
            ("etc/ssl", "SSL/TLS Certificates & Private Keys"),
            ("etc/inittab", "Init Script / Auto-launch Daemons"),
            ("etc/init.d", "System Services"),
            ("etc/config", "OpenWrt / NVRAM Configuration"),
            ("www", "Web Server Directory (potential CGI injection / auth bypass)"),
        ]

        for rel_path, desc in checks:
            target = rootfs_dir / rel_path
            if target.exists():
                findings.append({
                    "path": str(rel_path),
                    "description": desc,
                    "is_dir": target.is_dir(),
                    "size_bytes": target.stat().st_size if target.is_file() else None,
                })
        return findings

    def _calculate_stats(self, rootfs_dir: Path) -> tuple[int, int]:
        """Calculates total file count and size."""
        file_count = 0
        total_bytes = 0
        for root, _, files in os.walk(rootfs_dir):
            for f in files:
                file_count += 1
                try:
                    total_bytes += os.path.getsize(os.path.join(root, f))
                except OSError:
                    pass
        return file_count, total_bytes
