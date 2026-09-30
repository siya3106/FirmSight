"""
FirmSight Core Modules: Architecture Detection, Extraction, Emulation, Network, Dynamic Tracing, NVRAM, and Dependency Scanning.
"""

from .detector import ArchDetector
from .extractor import ExtractorEngine
from .emulator import QEMUEmulator
from .network import NetworkManager
from .tracer import DynamicTracer
from .nvram import NVRAMMock
from .dep_scanner import DependencyScanner

__all__ = [
    "ArchDetector",
    "ExtractorEngine",
    "QEMUEmulator",
    "NetworkManager",
    "DynamicTracer",
    "NVRAMMock",
    "DependencyScanner",
]
