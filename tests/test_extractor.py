"""
Unit tests for ExtractorEngine and Mock Firmware Generation
"""

import tempfile
from pathlib import Path
from firmsight.core.extractor import ExtractorEngine
from firmsight.utils.mock_firmware import create_mock_firmware

def test_mock_firmware_creation_and_extraction():
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        fw_binary = tmp_path / "test_firmware.bin"
        out_dir = tmp_path / "extracted"

        create_mock_firmware(fw_binary)
        assert fw_binary.exists()
        assert fw_binary.stat().st_size > 0

        extractor = ExtractorEngine(output_dir=out_dir)
        report = extractor.extract(fw_binary)

        assert report["success"] is True
        assert report["file_count"] > 0
        rootfs = Path(report["rootfs_path"])
        assert (rootfs / "etc" / "passwd").exists()
        assert (rootfs / "bin" / "busybox").exists()

        # Audit should flag passwd / shadow
        assert len(report["sensitive_files"]) >= 2

def test_filesystem_signature_scanning():
    with tempfile.TemporaryDirectory() as tmpdir:
        dummy_fw = Path(tmpdir) / "multi_fs.bin"

        # Construct blob with UBI, JFFS2, and CramFS signatures
        blob = bytearray(b"\x00" * 4096)
        blob[512:516] = b"UBI#"
        blob[1024:1026] = b"\x85\x19"
        blob[2048:2052] = b"\x45\x3d\xcd\x28"
        dummy_fw.write_bytes(blob)

        extractor = ExtractorEngine(output_dir=Path(tmpdir) / "out")
        sigs = extractor.scan_signatures(dummy_fw)

        types_found = [s["type"] for s in sigs]
        assert "UBI Superblock" in types_found
        assert "JFFS2 (Little Endian)" in types_found
        assert "CramFS (Little Endian)" in types_found

        offsets = {s["type"]: s["offset"] for s in sigs}
        assert offsets["UBI Superblock"] == 512
        assert offsets["JFFS2 (Little Endian)"] == 1024
        assert offsets["CramFS (Little Endian)"] == 2048

def test_ubi_and_cramfs_carving():
    with tempfile.TemporaryDirectory() as tmpdir:
        dummy_fw = Path(tmpdir) / "embedded_ubi.bin"
        out_dir = Path(tmpdir) / "carve_out"

        blob = bytearray(b"\xff" * 2048)
        blob[256:260] = b"UBI#"
        dummy_fw.write_bytes(blob)

        extractor = ExtractorEngine(output_dir=out_dir)
        report = extractor.extract(dummy_fw)

        assert report["success"] is True
        assert "carved" in report["method"]
        manifest = out_dir / "carved_manifest.txt"
        assert manifest.is_file()
        assert "UBI Superblock" in manifest.read_text()
