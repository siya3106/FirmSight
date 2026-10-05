"""
Virtual Sysfs and Procfs Hardware Profile Generator
Synthesizes virtual /proc and /sys pseudo-files inside the emulated rootfs
to prevent foreign architecture binaries from crashing when querying hardware specs.
"""

from pathlib import Path
from typing import Dict, Any, Optional

class SysfsMock:
    """Creates virtual /proc and /sys files tailored to foreign architectures (ARM, MIPS, x86)."""

    CPUINFO_PROFILES = {
        "ARM": (
            "processor\t: 0\n"
            "model name\t: ARMv7 Processor rev 1 (v7l)\n"
            "BogoMIPS\t: 1594.16\n"
            "Features\t: half thumb fastmult vfp edsp neon vfpv3 tls vfpd32\n"
            "CPU implementer\t: 0x41\n"
            "CPU architecture: 7\n"
            "CPU variant\t: 0x4\n"
            "CPU part\t: 0xc09\n"
            "CPU revision\t: 1\n"
            "Hardware\t: Broadcom BCM4709 / BCM5301X Dual-Core\n"
            "Revision\t: 0000\n"
            "Serial\t\t: 0000000000000000\n"
        ),
        "AArch64": (
            "processor\t: 0\n"
            "BogoMIPS\t: 40.00\n"
            "Features\t: fp asimd evtstrm aes pmull sha1 sha2 crc32 atomics\n"
            "CPU implementer\t: 0x41\n"
            "CPU architecture: 8\n"
            "CPU variant\t: 0x1\n"
            "CPU part\t: 0xd07\n"
            "CPU revision\t: 2\n"
            "Hardware\t: ARMv8 Cortex-A53 IoT Gateway\n"
        ),
        "MIPS": (
            "system type\t\t: MediaTek MT7628AN ver:1 eco:2\n"
            "machine\t\t\t: MediaTek MT7628AN evaluation board\n"
            "processor\t\t: 0\n"
            "cpu model\t\t: MIPS 24KEc V5.5\n"
            "BogoMIPS\t\t: 385.84\n"
            "wait instruction\t: yes\n"
            "microsecond timers\t: yes\n"
            "tlb_entries\t\t: 32\n"
            "extra interrupt vector\t: yes\n"
            "hardware watchpoint\t: yes, count: 4, address/irw mask: [0x0ffc, 0x0ffc, 0x0ffb, 0x0ffb]\n"
            "isa\t\t\t: mips1 mips2 mips32r1 mips32r2\n"
            "ASEs implemented\t: mips16 dsp\n"
            "shadow register sets\t: 1\n"
            "kscratch registers\t: 0\n"
            "package\t\t\t: 0\n"
            "core\t\t\t: 0\n"
            "VCED exceptions\t\t: not available\n"
            "VCEI exceptions\t\t: not available\n"
        ),
        "x86": (
            "processor\t: 0\n"
            "vendor_id\t: GenuineIntel\n"
            "cpu family\t: 6\n"
            "model\t\t: 79\n"
            "model name\t: Intel(R) Xeon(R) CPU E5-2673 v4 @ 2.30GHz\n"
            "stepping\t: 1\n"
            "cpu MHz\t\t: 2294.686\n"
            "cache size\t: 51200 KB\n"
            "fpu\t\t: yes\n"
            "flags\t\t: fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36\n"
        ),
    }

    MEMINFO_CONTENT = (
        "MemTotal:         262144 kB\n"
        "MemFree:          184320 kB\n"
        "MemAvailable:     204800 kB\n"
        "Buffers:            8192 kB\n"
        "Cached:            40960 kB\n"
        "SwapCached:            0 kB\n"
        "Active:            32768 kB\n"
        "Inactive:          24576 kB\n"
        "SwapTotal:             0 kB\n"
        "SwapFree:              0 kB\n"
        "Dirty:                 0 kB\n"
        "Writeback:             0 kB\n"
        "AnonPages:         16384 kB\n"
        "Mapped:             8192 kB\n"
        "Shmem:              2048 kB\n"
        "Slab:               8192 kB\n"
        "SReclaimable:       4096 kB\n"
        "SUnreclaim:         4096 kB\n"
    )

    VERSION_CONTENT = "Linux version 4.14.151 (builder@firmsight) (gcc version 7.3.0) #1 SMP PREEMPT 2026\n"

    NET_DEV_CONTENT = (
        "Inter-|   Receive                                                |  Transmit\n"
        " face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n"
        "    lo:       0       0    0    0    0     0          0         0        0       0    0    0    0     0       0          0\n"
        "  eth0: 1048576    2048    0    0    0     0          0         0  1048576    2048    0    0    0     0       0          0\n"
        "  br-lan: 1048576  2048    0    0    0     0          0         0  1048576    2048    0    0    0     0       0          0\n"
    )

    def __init__(self, rootfs_path: Path):
        self.rootfs_path = Path(rootfs_path).resolve()

    def provision_all(self, arch: str = "ARM") -> Dict[str, str]:
        """Provisions all standard /proc, /sys, and pseudo-devices in the target rootfs."""
        created = {}
        proc_dir = self.rootfs_path / "proc"
        sys_dir = self.rootfs_path / "sys"
        dev_dir = self.rootfs_path / "dev"

        proc_dir.mkdir(parents=True, exist_ok=True)
        sys_dir.mkdir(parents=True, exist_ok=True)
        dev_dir.mkdir(parents=True, exist_ok=True)

        # 1. /proc/cpuinfo
        cpu_text = self.CPUINFO_PROFILES.get(arch.upper(), self.CPUINFO_PROFILES["ARM"])
        (proc_dir / "cpuinfo").write_text(cpu_text, encoding="utf-8")
        created["/proc/cpuinfo"] = str(proc_dir / "cpuinfo")

        # 2. /proc/meminfo
        (proc_dir / "meminfo").write_text(self.MEMINFO_CONTENT, encoding="utf-8")
        created["/proc/meminfo"] = str(proc_dir / "meminfo")

        # 3. /proc/version
        (proc_dir / "version").write_text(self.VERSION_CONTENT, encoding="utf-8")
        created["/proc/version"] = str(proc_dir / "version")

        # 4. /proc/net/dev
        net_dir = proc_dir / "net"
        net_dir.mkdir(parents=True, exist_ok=True)
        (net_dir / "dev").write_text(self.NET_DEV_CONTENT, encoding="utf-8")
        created["/proc/net/dev"] = str(net_dir / "dev")

        # 5. /proc/sys/kernel/hostname & osrelease
        kernel_sys = proc_dir / "sys" / "kernel"
        kernel_sys.mkdir(parents=True, exist_ok=True)
        (kernel_sys / "hostname").write_text("FirmSight-Router\n", encoding="utf-8")
        (kernel_sys / "osrelease").write_text("4.14.151\n", encoding="utf-8")
        created["/proc/sys/kernel/hostname"] = str(kernel_sys / "hostname")

        # 6. /sys/class/net/eth0/address (Mock MAC address)
        eth0_dir = sys_dir / "class" / "net" / "eth0"
        eth0_dir.mkdir(parents=True, exist_ok=True)
        (eth0_dir / "address").write_text("00:11:22:33:44:55\n", encoding="utf-8")
        created["/sys/class/net/eth0/address"] = str(eth0_dir / "address")

        return created
