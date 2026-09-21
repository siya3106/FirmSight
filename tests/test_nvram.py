"""
Unit tests for NVRAM Mocking
"""

import tempfile
from pathlib import Path
from firmsight.core.nvram import NVRAMMock

def test_nvram_initialization():
    with tempfile.TemporaryDirectory() as tmpdir:
        rootfs = Path(tmpdir)
        nv = NVRAMMock(rootfs)
        nv_file = nv.initialize_mock({"custom_flag": "enabled"})

        assert nv_file.is_file()
        assert nv.get("lan_ipaddr") == "192.168.1.1"
        assert nv.get("custom_flag") == "enabled"

        # Update key
        nv.set("custom_flag", "disabled")
        assert nv.get("custom_flag") == "disabled"
