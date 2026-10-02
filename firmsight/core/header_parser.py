"""
Firmware Container and Image Header Parser
Parses common embedded firmware packaging formats without external tools:
- U-Boot uImage (header magic 0x27051956)
- Broadcom / OpenWrt TRX (header magic 'HDR0' / 0x30524448)
- TP-Link firmware image headers
"""

import struct
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional

class HeaderParser:
    """Parses firmware container headers to extract architecture, compression, kernel entrypoints, and sizes."""

    UIMAGE_MAGIC = 0x27051956
    TRX_MAGIC = b"HDR0"
    TPLINK_V1_MAGIC = 0x01000000
    TPLINK_V2_MAGIC = 0x02000000

    # U-Boot OS, Architecture, and Compression tables
    UIMAGE_ARCH = {
        1: "Alpha", 2: "ARM", 3: "x86", 4: "IA64", 5: "MIPS", 6: "MIPS64",
        7: "PowerPC", 8: "S390", 9: "SuperH", 10: "SPARC", 11: "SPARC64",
        12: "M68K", 14: "ARM64 / AArch64", 15: "RISC-V",
    }
    UIMAGE_TYPE = {
        1: "Standalone Program", 2: "OS Kernel Image", 3: "RAMDisk Image",
        4: "Multi-File Image", 5: "Firmware Image", 6: "Script", 7: "Filesystem Image",
    }
    UIMAGE_COMP = {
        0: "None (Uncompressed)", 1: "Gzip", 2: "Bzip2", 3: "LZMA", 4: "LZO", 5: "LZ4", 6: "Zstandard",
    }

    @classmethod
    def parse_file(cls, filepath: Path) -> List[Dict[str, Any]]:
        """Scans and extracts all identifiable container headers from a binary file."""
        path = Path(filepath).resolve()
        if not path.is_file():
            raise FileNotFoundError(f"Firmware binary not found: {path}")

        data = path.read_bytes()
        results: List[Dict[str, Any]] = []

        # 1. Scan for U-Boot uImage headers
        results.extend(cls._scan_uimage(data))

        # 2. Scan for Broadcom TRX headers
        results.extend(cls._scan_trx(data))

        return results

    @classmethod
    def _scan_uimage(cls, data: bytes) -> List[Dict[str, Any]]:
        """Parses U-Boot 64-byte image headers."""
        findings = []
        offset = 0
        target_magic = struct.pack(">I", cls.UIMAGE_MAGIC)

        while True:
            idx = data.find(target_magic, offset)
            if idx == -1 or idx + 64 > len(data):
                break

            hdr_bytes = data[idx : idx + 64]
            (
                magic, hcrc, time_epoch, data_size,
                load_addr, entry_point, dcrc,
                os_type, arch_code, img_type, comp_code
            ) = struct.unpack(">IIIIIIIBBBB", hdr_bytes[:36])

            img_name = hdr_bytes[36:68].split(b"\x00")[0].decode("ascii", errors="replace")
            dt_str = datetime.utcfromtimestamp(time_epoch).strftime("%Y-%m-%d %H:%M:%S UTC") if time_epoch > 0 else "N/A"

            findings.append({
                "format": "U-Boot uImage",
                "offset": idx,
                "hex_offset": f"0x{idx:08X}",
                "image_name": img_name or "Unnamed uImage",
                "arch": cls.UIMAGE_ARCH.get(arch_code, f"Unknown (0x{arch_code:02X})"),
                "image_type": cls.UIMAGE_TYPE.get(img_type, f"Type {img_type}"),
                "compression": cls.UIMAGE_COMP.get(comp_code, f"Comp {comp_code}"),
                "creation_time": dt_str,
                "data_size": data_size,
                "load_address": f"0x{load_addr:08X}",
                "entry_point": f"0x{entry_point:08X}",
                "header_crc": f"0x{hcrc:08X}",
                "data_crc": f"0x{dcrc:08X}",
            })

            offset = idx + 4

        return findings

    @classmethod
    def _scan_trx(cls, data: bytes) -> List[Dict[str, Any]]:
        """Parses Broadcom TRX headers (HDR0)."""
        findings = []
        offset = 0

        while True:
            idx = data.find(cls.TRX_MAGIC, offset)
            if idx == -1 or idx + 28 > len(data):
                break

            hdr_bytes = data[idx : idx + 28]
            magic, total_len, crc32, flags_version, offset0, offset1, offset2 = struct.unpack(
                "<4sIIIIII", hdr_bytes
            )

            version = (flags_version >> 16) & 0xFFFF
            flags = flags_version & 0xFFFF

            findings.append({
                "format": "Broadcom TRX",
                "offset": idx,
                "hex_offset": f"0x{idx:08X}",
                "version": version,
                "flags": f"0x{flags:04X}",
                "total_size": total_len,
                "crc32": f"0x{crc32:08X}",
                "partition_offsets": [
                    {"partition": "Kernel / Loader", "offset": f"0x{offset0:08X}", "rel_bytes": offset0},
                    {"partition": "Root Filesystem", "offset": f"0x{offset1:08X}", "rel_bytes": offset1},
                    {"partition": "Extended / Overlay", "offset": f"0x{offset2:08X}", "rel_bytes": offset2},
                ],
            })

            offset = idx + 4

        return findings
