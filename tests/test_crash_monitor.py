"""
Unit tests for CrashMonitor
"""

from firmsight.analysis.crash_monitor import CrashMonitor

def test_sigsegv_evaluation():
    stderr_sample = "qemu: uncaught target signal 11 (Segmentation fault) - core dumped\npc: 0x41414141 sp: 0x7efdf120"
    res = CrashMonitor.evaluate_exit_code(139, stderr_sample)

    assert res is not None
    assert res["signal"] == "SIGSEGV"
    assert res["severity"] == "CRITICAL"
    assert res["is_memory_fault"] is True
    assert res["registers"].get("pc") == "0x41414141"
    assert res["registers"].get("sp") == "0x7efdf120"

def test_clean_exit_evaluation():
    res = CrashMonitor.evaluate_exit_code(0)
    assert res is None
