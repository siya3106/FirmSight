"""
FirmSight Core Modules: Architecture Detection, Extraction, Emulation, Network, Dynamic Tracing, NVRAM, Dependency Scanning, and Header Parsing.
"""

from .detector import ArchDetector
from .extractor import ExtractorEngine
from .emulator import QEMUEmulator
from .network import NetworkManager
from .tracer import DynamicTracer
from .nvram import NVRAMMock
from .dep_scanner import DependencyScanner
from .header_parser import HeaderParser

__all__ = [
    "ArchDetector",
    "ExtractorEngine",
    "QEMUEmulator",
    "NetworkManager",
    "DynamicTracer",
    "NVRAMMock",
    "DependencyScanner",
    "HeaderParser",
]
