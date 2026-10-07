"""
Unit tests for QEMUEmulator Process Supervisor and Watchdog
"""

import tempfile
import time
from pathlib import Path
from firmsight.core.emulator import QEMUEmulator

def test_emulator_lifecycle_and_stdout():
    with tempfile.TemporaryDirectory() as tmpdir:
        rootfs = Path(tmpdir)
        stdout_lines = []

        emulator = QEMUEmulator(
            rootfs_path=rootfs,
            qemu_binary="qemu-arm-static",
            timeout_seconds=None,
            on_stdout=lambda line: stdout_lines.append(line),
        )

        started = emulator.start_user_mode(target_binary="/usr/sbin/uhttpd")
        assert started is True
        assert emulator.is_running is True
        assert emulator.pid is not None

        # Allow output to stream
        time.sleep(1.5)
        assert len(stdout_lines) > 0

        # Stop process
        emulator.stop(grace_period=0.5)
        assert emulator.is_running is False
        assert emulator.exit_code is not None

def test_emulator_watchdog_timeout():
    with tempfile.TemporaryDirectory() as tmpdir:
        rootfs = Path(tmpdir)
        stderr_lines = []

        emulator = QEMUEmulator(
            rootfs_path=rootfs,
            qemu_binary="qemu-arm-static",
            timeout_seconds=2,  # 2-second timeout
            on_stderr=lambda line: stderr_lines.append(line),
        )

        started = emulator.start_user_mode(target_binary="/usr/sbin/uhttpd")
        assert started is True

        # Wait for watchdog to trigger
        time.sleep(3.5)

        assert emulator.is_running is False
        assert emulator.timed_out is True
        assert any("WATCHDOG" in line for line in stderr_lines)
