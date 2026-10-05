"""
Unit tests for SysfsMock
"""

import tempfile
from pathlib import Path
from firmsight.core.sysfs_mock import SysfsMock

def test_arm_sysfs_provisioning():
    with tempfile.TemporaryDirectory() as tmpdir:
        rootfs = Path(tmpdir)
        mock = SysfsMock(rootfs)
        created = mock.provision_all(arch="ARM")

        assert "/proc/cpuinfo" in created
        assert "/proc/meminfo" in created
        assert "/proc/net/dev" in created
        assert "/sys/class/net/eth0/address" in created

        cpuinfo_text = (rootfs / "proc" / "cpuinfo").read_text()
        assert "ARMv7 Processor" in cpuinfo_text
        assert "Broadcom" in cpuinfo_text

        meminfo_text = (rootfs / "proc" / "meminfo").read_text()
        assert "MemTotal" in meminfo_text

def test_mips_sysfs_provisioning():
    with tempfile.TemporaryDirectory() as tmpdir:
        rootfs = Path(tmpdir)
        mock = SysfsMock(rootfs)
        mock.provision_all(arch="MIPS")

        cpuinfo_text = (rootfs / "proc" / "cpuinfo").read_text()
        assert "MIPS 24KEc" in cpuinfo_text
        assert "MediaTek" in cpuinfo_text
