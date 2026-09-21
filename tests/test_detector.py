"""
Unit tests for ArchDetector
"""

import tempfile
from pathlib import Path
from firmsight.core.detector import ArchDetector
from firmsight.utils.mock_firmware import generate_mock_arm_elf

def test_arm_elf_detection():
    arm_bytes = generate_mock_arm_elf()
    with tempfile.NamedTemporaryFile(suffix=".elf", delete=False) as tmp:
        tmp.write(arm_bytes)
        tmp_path = Path(tmp.name)

    try:
        res = ArchDetector.inspect_file(tmp_path)
        assert res is not None
        assert res["valid_elf"] is True
        assert res["arch"] == "ARM"
        assert res["bitness"] == 32
        assert res["endianness"] == "little"
        assert res["qemu_target"] == "qemu-arm-static"
    finally:
        tmp_path.unlink(missing_ok=True)

def test_invalid_file_detection():
    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as tmp:
        tmp.write(b"This is not an ELF binary")
        tmp_path = Path(tmp.name)

    try:
        res = ArchDetector.inspect_file(tmp_path)
        assert res is None
    finally:
        tmp_path.unlink(missing_ok=True)
