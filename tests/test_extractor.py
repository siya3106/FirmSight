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
