"""
Unit tests for DependencyScanner
"""

import tempfile
from pathlib import Path
from firmsight.core.dep_scanner import DependencyScanner
from firmsight.utils.mock_firmware import generate_mock_arm_elf

def test_non_elf_dependency_scan():
    with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as tmp:
        tmp.write(b"Plain text file, not ELF")
        tmp_path = Path(tmp.name)

    try:
        scanner = DependencyScanner(rootfs_path=tmp_path.parent)
        res = scanner.inspect_binary(tmp_path)
        assert res.get("is_elf") is False
    finally:
        tmp_path.unlink(missing_ok=True)

def test_static_arm_elf_scan():
    with tempfile.NamedTemporaryFile(suffix=".elf", delete=False) as tmp:
        tmp.write(generate_mock_arm_elf())
        tmp_path = Path(tmp.name)

    try:
        scanner = DependencyScanner(rootfs_path=tmp_path.parent)
        res = scanner.inspect_binary(tmp_path)
        assert res.get("is_elf") is True
        assert res.get("bitness") == 32
        assert res.get("endianness") == "little"
        # Statically linked or header-only ELF has no missing dynamic libs
        assert len(res.get("missing_libraries", [])) == 0
    finally:
        tmp_path.unlink(missing_ok=True)

def test_rootfs_dependency_indexing():
    with tempfile.TemporaryDirectory() as tmpdir:
        rootfs = Path(tmpdir)

        # Create lib structure
        lib_dir = rootfs / "lib"
        lib_dir.mkdir(parents=True)
        (lib_dir / "libc.so.0").write_bytes(b"dummy libc")
        (lib_dir / "libpthread.so.0").write_bytes(b"dummy pthread")

        scanner = DependencyScanner(rootfs_path=rootfs)
        libs = scanner.get_available_libraries()

        assert "libc.so.0" in libs
        assert "libpthread.so.0" in libs
        assert len(libs) == 2
