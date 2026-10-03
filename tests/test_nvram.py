"""
Unit tests for NVRAM Mocking, Vendor Profiles, and Import/Export
"""

import tempfile
from pathlib import Path
from firmsight.core.nvram import NVRAMMock

def test_nvram_initialization():
    with tempfile.TemporaryDirectory() as tmpdir:
        rootfs = Path(tmpdir)
        nv = NVRAMMock(rootfs)
        nv_file = nv.initialize_mock(custom_keys={"custom_flag": "enabled"})

        assert nv_file.is_file()
        assert nv.get("lan_ipaddr") == "192.168.1.1"
        assert nv.get("custom_flag") == "enabled"

        # Update key
        nv.set("custom_flag", "disabled")
        assert nv.get("custom_flag") == "disabled"

def test_vendor_profiles_and_stub():
    with tempfile.TemporaryDirectory() as tmpdir:
        rootfs = Path(tmpdir)
        nv = NVRAMMock(rootfs)

        # Test D-Link profile
        nv.initialize_mock(vendor="dlink", custom_keys={"hw_rev": "B2"})
        assert nv.get("model_name") == "DIR-850L"
        assert nv.get("hw_rev") == "B2"

        # Verify stub script created in /usr/sbin/nvram
        stub = rootfs / "usr" / "sbin" / "nvram"
        assert stub.is_file()
        assert "firmsight_nvram.json" in stub.read_text()

def test_nvram_export_import():
    with tempfile.TemporaryDirectory() as tmpdir:
        rootfs = Path(tmpdir)
        nv = NVRAMMock(rootfs)
        nv.initialize_mock(vendor="netgear")

        # Export to .env
        env_file = Path(tmpdir) / "test.env"
        nv.export_data(env_file, fmt="env")
        assert env_file.is_file()
        content = env_file.read_text()
        assert "model_name=R7000" in content

        # Append new key to .env and import back
        env_file.write_text(content + "\ncustom_secret_key=xyz123\n")
        imported = nv.import_data(env_file)
        assert imported.get("custom_secret_key") == "xyz123"
        assert nv.get("custom_secret_key") == "xyz123"
