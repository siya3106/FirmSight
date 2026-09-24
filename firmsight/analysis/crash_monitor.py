"""
Crash and Fault Monitor
Monitors emulated processes for abnormal termination, signal faults (SIGSEGV, SIGBUS, SIGABRT),
and parses register states to diagnose memory corruption and stack exhaustion safely.
"""

import re
from typing import Dict, Any, Optional, List

class CrashMonitor:
    """Detects, classifies, and reports process faults and abnormal terminations."""

    SIGNAL_MAP = {
        139: {"signal": "SIGSEGV", "name": "Segmentation Fault", "severity": "CRITICAL", "cwe": "CWE-119"},
        134: {"signal": "SIGABRT", "name": "Aborted (Assertion / Heap Corruption)", "severity": "HIGH", "cwe": "CWE-134"},
        135: {"signal": "SIGBUS",  "name": "Bus Error (Alignment Fault)", "severity": "HIGH", "cwe": "CWE-119"},
        136: {"signal": "SIGFPE",  "name": "Floating Point Exception / Div by Zero", "severity": "MEDIUM", "cwe": "CWE-369"},
        132: {"signal": "SIGILL",  "name": "Illegal Instruction", "severity": "MEDIUM", "cwe": "CWE-758"},
    }

    @classmethod
    def evaluate_exit_code(cls, exit_code: int, stderr_log: str = "") -> Optional[Dict[str, Any]]:
        """Evaluates a process returncode and parses signal details."""
        if exit_code == 0:
            return None

        fault_info = cls.SIGNAL_MAP.get(exit_code)
        if not fault_info:
            # Check for standard negative signal notation (e.g. -11 for SIGSEGV)
            pos_signal = 128 + abs(exit_code) if exit_code < 0 else exit_code
            fault_info = cls.SIGNAL_MAP.get(pos_signal, {
                "signal": f"CODE_{exit_code}",
                "name": f"Non-zero exit ({exit_code})",
                "severity": "LOW",
                "cwe": "CWE-388",
            })

        register_state = cls.parse_registers(stderr_log)
        is_memory_fault = fault_info["signal"] in ("SIGSEGV", "SIGBUS", "SIGABRT")

        return {
            "exit_code": exit_code,
            "signal": fault_info["signal"],
            "description": fault_info["name"],
            "severity": fault_info["severity"],
            "cwe": fault_info["cwe"],
            "is_memory_fault": is_memory_fault,
            "registers": register_state,
            "stderr_snippet": stderr_log[-500:] if stderr_log else "",
        }

    @staticmethod
    def parse_registers(log_text: str) -> Dict[str, str]:
        """Extracts common CPU register values from QEMU or GDB crash dumps."""
        registers = {}
        patterns = {
            "pc": r"(?:pc|eip|rip)\s*[:=]\s*(0x[0-9a-fA-F]+)",
            "sp": r"(?:sp|esp|rsp)\s*[:=]\s*(0x[0-9a-fA-F]+)",
            "lr": r"(?:lr)\s*[:=]\s*(0x[0-9a-fA-F]+)",
            "r0": r"(?:r0|eax|rax)\s*[:=]\s*(0x[0-9a-fA-F]+)",
            "fault_addr": r"(?:fault addr|badaddr|addr)\s*[:=]\s*(0x[0-9a-fA-F]+)",
        }

        for reg, pat in patterns.items():
            match = re.search(pat, log_text, re.IGNORECASE)
            if match:
                registers[reg] = match.group(1)

        return registers
