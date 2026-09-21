"""
ELF Architecture and Endianness Detector
Parses binary headers directly without relying on external dependencies like readelf or file.
"""

import struct
from pathlib import Path
from typing import Dict, Any, Optional

# Standard e_machine mapping from Linux elf.h
ELF_MACHINES = {
    0x02: "SPARC",
    0x03: "x86",
    0x08: "MIPS",
    0x14: "PowerPC",
    0x15: "PowerPC64",
    0x28: "ARM",
    0x2A: "SuperH",
    0x32: "IA-64",
    0x3E: "x86_64",
    0xB7: "AArch64",
    0xF3: "RISC-V",
}

class ArchDetector:
    """Detects CPU architecture, endianness, and word size from ELF binaries."""

    @staticmethod
    def inspect_file(filepath: Path) -> Optional[Dict[str, Any]]:
        """Inspects an ELF file and returns architecture metadata."""
        path = Path(filepath)
        if not path.is_file():
            return None

        try:
            with open(path, "rb") as f:
                header = f.read(52)
                if len(header) < 16 or header[:4] != b"\x7fELF":
                    return None

                # Byte 4: EI_CLASS (1 = 32-bit, 2 = 64-bit)
                ei_class = header[4]
                bitness = 32 if ei_class == 1 else (64 if ei_class == 2 else 0)

                # Byte 5: EI_DATA (1 = little-endian, 2 = big-endian)
                ei_data = header[5]
                endianness = "little" if ei_data == 1 else ("big" if ei_data == 2 else "unknown")
                fmt_char = "<" if endianness == "little" else ">"

                # Byte 16..17: e_type, Byte 18..19: e_machine
                e_type, e_machine = struct.unpack(f"{fmt_char}HH", header[16:20])
                arch_name = ELF_MACHINES.get(e_machine, f"Unknown (0x{e_machine:02X})")

                # Map architecture to QEMU static binary target
                qemu_target = ArchDetector._get_qemu_target(arch_name, bitness, endianness)

                return {
                    "valid_elf": True,
                    "arch": arch_name,
                    "bitness": bitness,
                    "endianness": endianness,
                    "e_machine": e_machine,
                    "qemu_target": qemu_target,
                    "file_path": str(path),
                }
        except Exception:
            return None

    @staticmethod
    def _get_qemu_target(arch: str, bitness: int, endianness: str) -> str:
        """Derives the corresponding QEMU static emulator binary name."""
        if arch == "ARM":
            return "qemu-arm-static"
        elif arch == "AArch64":
            return "qemu-aarch64-static"
        elif arch == "MIPS":
            if endianness == "little":
                return "qemu-mipsel-static" if bitness == 32 else "qemu-mips64el-static"
            return "qemu-mips-static" if bitness == 32 else "qemu-mips64-static"
        elif arch == "x86":
            return "qemu-i386-static"
        elif arch == "x86_64":
            return "qemu-x86_64-static"
        elif arch == "RISC-V":
            return "qemu-riscv64-static" if bitness == 64 else "qemu-riscv32-static"
        return "qemu-unknown"

    @classmethod
    def scan_rootfs(cls, rootfs_path: Path) -> Optional[Dict[str, Any]]:
        """Scans well-known binary locations in a rootfs to identify device architecture."""
        rootfs_path = Path(rootfs_path)
        candidates = [
            rootfs_path / "bin" / "busybox",
            rootfs_path / "bin" / "sh",
            rootfs_path / "sbin" / "init",
            rootfs_path / "usr" / "sbin" / "uhttpd",
            rootfs_path / "usr" / "sbin" / "httpd",
            rootfs_path / "usr" / "bin" / "boa",
        ]

        for cand in candidates:
            if cand.exists():
                res = cls.inspect_file(cand)
                if res:
                    return res

        # Fallback: scan any ELF in /bin or /sbin
        for search_dir in [rootfs_path / "bin", rootfs_path / "sbin", rootfs_path / "usr" / "bin"]:
            if search_dir.is_dir():
                for item in search_dir.iterdir():
                    if item.is_file():
                        res = cls.inspect_file(item)
                        if res:
                            return res
        return None
