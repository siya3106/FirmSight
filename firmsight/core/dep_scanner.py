"""
ELF Dynamic Dependency and Shared Library Mapper
Parses ELF headers and string tables directly without external dependencies (no readelf or ldd required).
Extracts DT_NEEDED shared libraries, DT_RPATH/DT_RUNPATH, and verifies their presence in the rootfs.
"""

import os
import struct
from pathlib import Path
from typing import Dict, Any, List, Optional, Set

class DependencyScanner:
    """Scans ELF binaries for runtime shared library requirements and flags missing dependencies."""

    # Standard ELF segment and dynamic tag constants
    PT_DYNAMIC = 2
    DT_NULL = 0
    DT_NEEDED = 1
    DT_STRTAB = 5
    DT_RPATH = 15
    DT_RUNPATH = 29

    STANDARD_LIB_DIRS = ["lib", "usr/lib", "usr/local/lib", "lib32", "lib64"]

    def __init__(self, rootfs_path: Path):
        self.rootfs_path = Path(rootfs_path).resolve()
        self._available_libraries: Optional[Set[str]] = None

    def get_available_libraries(self) -> Set[str]:
        """Indexes all available shared libraries (.so*) present in the rootfs."""
        if self._available_libraries is not None:
            return self._available_libraries

        libs = set()
        if self.rootfs_path.is_dir():
            for root, _, files in os.walk(self.rootfs_path):
                for f in files:
                    if ".so" in f or f.endswith(".so"):
                        libs.add(f)
        self._available_libraries = libs
        return self._available_libraries

    def inspect_binary(self, binary_path: Path) -> Dict[str, Any]:
        """Parses an individual ELF binary and determines needed libraries and missing dependencies."""
        path = Path(binary_path).resolve()
        if not path.is_file():
            return {"error": f"File not found: {path}"}

        deps_info = self._parse_elf_dynamic(path)
        if not deps_info.get("is_elf"):
            return {"is_elf": False, "file": str(path)}

        available = self.get_available_libraries()
        needed = deps_info.get("needed", [])
        missing = [lib for lib in needed if lib not in available]

        return {
            "is_elf": True,
            "file": str(path),
            "bitness": deps_info.get("bitness"),
            "endianness": deps_info.get("endianness"),
            "needed_libraries": needed,
            "rpaths": deps_info.get("rpaths", []),
            "missing_libraries": missing,
            "has_missing": len(missing) > 0,
        }

    def scan_rootfs(self) -> Dict[str, Any]:
        """Scans all executable binaries in /bin, /sbin, /usr/bin, /usr/sbin for dependency health."""
        target_dirs = ["bin", "sbin", "usr/bin", "usr/sbin"]
        binaries_audited = []
        total_missing = 0

        for td in target_dirs:
            d = self.rootfs_path / td
            if d.is_dir():
                for item in d.iterdir():
                    if item.is_file():
                        info = self.inspect_binary(item)
                        if info.get("is_elf"):
                            binaries_audited.append(info)
                            if info.get("has_missing"):
                                total_missing += len(info.get("missing_libraries", []))

        return {
            "rootfs": str(self.rootfs_path),
            "binaries_count": len(binaries_audited),
            "total_missing_dependencies": total_missing,
            "binaries": binaries_audited,
        }

    def _parse_elf_dynamic(self, filepath: Path) -> Dict[str, Any]:
        """Pure-Python ELF dynamic table and string table extractor."""
        try:
            with open(filepath, "rb") as f:
                ident = f.read(16)
                if len(ident) < 16 or ident[:4] != b"\x7fELF":
                    return {"is_elf": False}

                ei_class = ident[4]  # 1 = 32-bit, 2 = 64-bit
                ei_data = ident[5]   # 1 = little-endian, 2 = big-endian
                is_32 = ei_class == 1
                endian = "<" if ei_data == 1 else ">"

                # Read ELF header
                if is_32:
                    f.seek(16)
                    hdr = f.read(36)
                    e_phoff, e_shoff, e_flags, e_ehsize, e_phentsize, e_phnum = struct.unpack(
                        f"{endian}IIIIHH", hdr[12:32]
                    )
                else:
                    f.seek(16)
                    hdr = f.read(48)
                    e_phoff, e_shoff, e_flags, e_ehsize, e_phentsize, e_phnum = struct.unpack(
                        f"{endian}QQIIHH", hdr[16:44]
                    )

                # Find PT_DYNAMIC segment
                dynamic_offset = None
                dynamic_size = 0

                for i in range(e_phnum):
                    f.seek(e_phoff + i * e_phentsize)
                    if is_32:
                        phdr = f.read(32)
                        p_type, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz = struct.unpack(
                            f"{endian}IIIIII", phdr[:24]
                        )
                    else:
                        phdr = f.read(56)
                        p_type, p_flags, p_offset, p_vaddr, p_paddr, p_filesz = struct.unpack(
                            f"{endian}IIQQQQ", phdr[:32]
                        )

                    if p_type == self.PT_DYNAMIC:
                        dynamic_offset = p_offset
                        dynamic_size = p_filesz
                        break

                if dynamic_offset is None or dynamic_size == 0:
                    return {
                        "is_elf": True,
                        "bitness": 32 if is_32 else 64,
                        "endianness": "little" if ei_data == 1 else "big",
                        "needed": [],
                        "rpaths": [],
                    }

                # Read dynamic tags
                needed_str_offsets = []
                rpath_str_offsets = []
                strtab_vaddr = None

                f.seek(dynamic_offset)
                entry_size = 8 if is_32 else 16
                num_entries = dynamic_size // entry_size

                for _ in range(num_entries):
                    if is_32:
                        tag, val = struct.unpack(f"{endian}II", f.read(8))
                    else:
                        tag, val = struct.unpack(f"{endian}QQ", f.read(16))

                    if tag == self.DT_NULL:
                        break
                    elif tag == self.DT_NEEDED:
                        needed_str_offsets.append(val)
                    elif tag in (self.DT_RPATH, self.DT_RUNPATH):
                        rpath_str_offsets.append(val)
                    elif tag == self.DT_STRTAB:
                        strtab_vaddr = val

                # Locate string table (fallback: scan for null-terminated strings around dynamic strings)
                f.seek(0)
                full_binary = f.read()

                # Extract strings at string table offsets
                needed_libs = []
                for offset in needed_str_offsets:
                    # In statically packed or raw files, read string starting from candidate offset
                    s = self._read_string_at(full_binary, strtab_vaddr, offset, is_32)
                    if s:
                        needed_libs.append(s)

                rpaths = []
                for offset in rpath_str_offsets:
                    s = self._read_string_at(full_binary, strtab_vaddr, offset, is_32)
                    if s:
                        rpaths.append(s)

                return {
                    "is_elf": True,
                    "bitness": 32 if is_32 else 64,
                    "endianness": "little" if ei_data == 1 else "big",
                    "needed": needed_libs,
                    "rpaths": rpaths,
                }
        except Exception:
            return {"is_elf": False}

    def _read_string_at(self, data: bytes, strtab_vaddr: Optional[int], offset: int, is_32: bool) -> Optional[str]:
        """Resolves a string table offset to a string."""
        if strtab_vaddr and strtab_vaddr < len(data):
            cand_start = strtab_vaddr + offset
            if cand_start < len(data):
                cand_end = data.find(b"\x00", cand_start)
                if cand_end != -1 and cand_end - cand_start < 128:
                    try:
                        return data[cand_start:cand_end].decode("ascii")
                    except Exception:
                        pass

        # Fallback: scan for common libc/lib pattern around candidate offsets
        return None
