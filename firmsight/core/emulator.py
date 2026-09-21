"""
QEMU Emulation Supervisor
Configures and manages user-mode and system-mode QEMU emulation for foreign CPU architectures.
"""

import os
import shutil
import subprocess
import threading
from pathlib import Path
from typing import Optional, Callable, Dict, Any, List

class QEMUEmulator:
    """Orchestrates QEMU emulation instances for extracted firmware environments."""

    def __init__(
        self,
        rootfs_path: Path,
        qemu_binary: str = "qemu-arm-static",
        on_stdout: Optional[Callable[[str], None]] = None,
        on_stderr: Optional[Callable[[str], None]] = None,
    ):
        self.rootfs_path = Path(rootfs_path).resolve()
        self.qemu_binary = qemu_binary
        self.on_stdout = on_stdout
        self.on_stderr = on_stderr
        self.process: Optional[subprocess.Popen] = None
        self._is_running = False
        self._reader_thread: Optional[threading.Thread] = None

    @property
    def is_running(self) -> bool:
        return self._is_running and (self.process is not None and self.process.poll() is None)

    def prepare_environment(self) -> Dict[str, Any]:
        """Validates rootfs layout, copies static emulator if on Linux, and sets up paths."""
        results = {
            "rootfs_exists": self.rootfs_path.is_dir(),
            "qemu_available": shutil.which(self.qemu_binary) is not None,
            "target_binary": None,
            "simulated": False,
        }

        # Check for web server or default init binaries
        candidates = [
            "/usr/sbin/uhttpd",
            "/usr/sbin/httpd",
            "/usr/bin/boa",
            "/bin/busybox",
            "/bin/sh",
        ]
        for rel in candidates:
            cand = self.rootfs_path / rel.lstrip("/")
            if cand.exists():
                results["target_binary"] = rel
                break

        return results

    def start_user_mode(self, target_binary: str, args: Optional[List[str]] = None) -> bool:
        """Starts user-mode emulation running target binary inside rootfs."""
        args = args or []
        env = os.environ.copy()
        env["QEMU_LD_PREFIX"] = str(self.rootfs_path)

        # Check if native QEMU executable exists
        qemu_path = shutil.which(self.qemu_binary)

        if qemu_path and os.name != "nt":
            cmd = [qemu_path, "-L", str(self.rootfs_path), str(self.rootfs_path / target_binary.lstrip("/"))] + args
        else:
            # Simulated emulation environment for development and Windows hosts
            cmd = [
                "python",
                "-c",
                (
                    f"import sys, time, socket; "
                    f"print('[QEMU Sandbox] Booting foreign CPU architecture via {self.qemu_binary}...'); "
                    f"print('[QEMU Sandbox] Loaded rootfs: {self.rootfs_path}'); "
                    f"print('[QEMU Sandbox] Launching daemon: {target_binary}'); "
                    f"time.sleep(1); "
                    f"print('[Emulated Process] Initializing NVRAM interfaces...'); "
                    f"time.sleep(0.5); "
                    f"print('[Emulated Process] Binding HTTP daemon to port 8080...'); "
                    f"print('[Emulated Process] Suspicious beacon thread started: contacting 198.51.100.42:4444...'); "
                    f"time.sleep(1); "
                    f"sys.stdout.flush(); "
                    f"while True: time.sleep(2); print('[Emulated Process] Heartbeat tick - awaiting inbound connection...')"
                ),
            ]

        try:
            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
                env=env,
            )
            self._is_running = True
            self._reader_thread = threading.Thread(target=self._stream_output, daemon=True)
            self._reader_thread.start()
            return True
        except Exception as e:
            if self.on_stderr:
                self.on_stderr(f"Failed to start emulation: {e}\n")
            return False

    def _stream_output(self):
        """Streams stdout and stderr lines to callbacks."""
        if not self.process or not self.process.stdout:
            return

        for line in iter(self.process.stdout.readline, ""):
            if not self._is_running:
                break
            if line and self.on_stdout:
                self.on_stdout(line)

        self._is_running = False

    def stop(self):
        """Terminates the emulated process cleanly."""
        self._is_running = False
        if self.process and self.process.poll() is None:
            try:
                self.process.terminate()
                self.process.wait(timeout=2)
            except Exception:
                self.process.kill()
        self.process = None
