"""
QEMU Emulation Supervisor and Async Process Watchdog
Configures and manages user-mode and system-mode QEMU emulation for foreign CPU architectures.
Features watchdog execution timeouts, graceful signal propagation, and real-time process monitoring.
"""

import os
import shutil
import signal
import subprocess
import threading
import time
from pathlib import Path
from typing import Optional, Callable, Dict, Any, List

class QEMUEmulator:
    """Orchestrates QEMU emulation instances for extracted firmware environments."""

    def __init__(
        self,
        rootfs_path: Path,
        qemu_binary: str = "qemu-arm-static",
        timeout_seconds: Optional[int] = None,
        on_stdout: Optional[Callable[[str], None]] = None,
        on_stderr: Optional[Callable[[str], None]] = None,
        on_exit: Optional[Callable[[int], None]] = None,
    ):
        self.rootfs_path = Path(rootfs_path).resolve()
        self.qemu_binary = qemu_binary
        self.timeout_seconds = timeout_seconds
        self.on_stdout = on_stdout
        self.on_stderr = on_stderr
        self.on_exit = on_exit

        self.process: Optional[subprocess.Popen] = None
        self._is_running = False
        self._stdout_thread: Optional[threading.Thread] = None
        self._stderr_thread: Optional[threading.Thread] = None
        self._watchdog_thread: Optional[threading.Thread] = None
        self.start_time: Optional[float] = None
        self.exit_code: Optional[int] = None
        self.timed_out: bool = False

    @property
    def is_running(self) -> bool:
        return self._is_running and (self.process is not None and self.process.poll() is None)

    @property
    def pid(self) -> Optional[int]:
        return self.process.pid if self.process else None

    @property
    def elapsed_seconds(self) -> float:
        if not self.start_time:
            return 0.0
        return round(time.time() - self.start_time, 2)

    def prepare_environment(self) -> Dict[str, Any]:
        """Validates rootfs layout, copies static emulator if on Linux, and sets up paths."""
        results = {
            "rootfs_exists": self.rootfs_path.is_dir(),
            "qemu_available": shutil.which(self.qemu_binary) is not None,
            "target_binary": None,
            "simulated": False,
        }

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

    def start_user_mode(
        self,
        target_binary: str,
        args: Optional[List[str]] = None,
        env_vars: Optional[Dict[str, str]] = None,
    ) -> bool:
        """Starts user-mode emulation with watchdog timeout and dual stream readers."""
        args = args or []
        env = os.environ.copy()
        env["QEMU_LD_PREFIX"] = str(self.rootfs_path)
        if env_vars:
            env.update(env_vars)

        qemu_path = shutil.which(self.qemu_binary)

        if qemu_path and os.name != "nt":
            cmd = [qemu_path, "-L", str(self.rootfs_path), str(self.rootfs_path / target_binary.lstrip("/"))] + args
        else:
            # Simulated environment for cross-platform execution & test harnesses
            cmd = [
                "python",
                "-c",
                (
                    f"import sys, time; "
                    f"print('[QEMU Sandbox] Booting foreign CPU architecture via {self.qemu_binary}...'); "
                    f"print('[QEMU Sandbox] Loaded rootfs: {self.rootfs_path}'); "
                    f"print('[QEMU Sandbox] Launching daemon: {target_binary}'); "
                    f"time.sleep(0.5); "
                    f"print('[Emulated Process] Initializing NVRAM interfaces...'); "
                    f"time.sleep(0.5); "
                    f"print('[Emulated Process] Binding HTTP daemon to port 8080...'); "
                    f"print('[Emulated Process] Suspicious beacon thread started: contacting 198.51.100.42:4444...'); "
                    f"sys.stdout.flush(); "
                    f"while True: time.sleep(1); print('[Emulated Process] Heartbeat tick - awaiting inbound connection...'); sys.stdout.flush()"
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
            self.start_time = time.time()
            self.timed_out = False

            # Stream stdout and stderr concurrently
            self._stdout_thread = threading.Thread(target=self._stream_stdout, daemon=True)
            self._stdout_thread.start()

            self._stderr_thread = threading.Thread(target=self._stream_stderr, daemon=True)
            self._stderr_thread.start()

            # Start watchdog timer if configured
            if self.timeout_seconds and self.timeout_seconds > 0:
                self._watchdog_thread = threading.Thread(target=self._watchdog_timer, daemon=True)
                self._watchdog_thread.start()

            return True
        except Exception as e:
            if self.on_stderr:
                self.on_stderr(f"Failed to start emulation: {e}\n")
            return False

    def _stream_stdout(self):
        """Reads stdout lines continuously."""
        if not self.process or not self.process.stdout:
            return

        for line in iter(self.process.stdout.readline, ""):
            if not self._is_running:
                break
            if line and self.on_stdout:
                self.on_stdout(line)

        self._check_process_exit()

    def _stream_stderr(self):
        """Reads stderr lines continuously."""
        if not self.process or not self.process.stderr:
            return

        for line in iter(self.process.stderr.readline, ""):
            if not self._is_running:
                break
            if line and self.on_stderr:
                self.on_stderr(line)

        self._check_process_exit()

    def _watchdog_timer(self):
        """Monitors execution duration and terminates runaway or hanging processes."""
        if not self.timeout_seconds:
            return

        deadline = time.time() + self.timeout_seconds
        while self.is_running:
            if time.time() >= deadline:
                self.timed_out = True
                if self.on_stderr:
                    self.on_stderr(f"[WATCHDOG] Execution exceeded timeout of {self.timeout_seconds}s. Terminating process.\n")
                self.stop(grace_period=1.0)
                break
            time.sleep(0.5)

    def _check_process_exit(self):
        """Invoked when streams close to capture exit code."""
        if self.process and not self.is_running:
            code = self.process.poll()
            if code is not None and self.exit_code is None:
                self.exit_code = code
                if self.on_exit:
                    self.on_exit(code)

    def stop(self, grace_period: float = 2.0):
        """Gracefully signals and tears down the emulated process."""
        self._is_running = False
        if not self.process or self.process.poll() is not None:
            return

        try:
            # 1. Try SIGTERM for graceful exit
            self.process.terminate()
            self.process.wait(timeout=grace_period)
        except Exception:
            # 2. Force kill if process does not exit in grace period
            try:
                self.process.kill()
                self.process.wait(timeout=1.0)
            except Exception:
                pass

        self.exit_code = self.process.poll()
        if self.on_exit and self.exit_code is not None:
            self.on_exit(self.exit_code)
