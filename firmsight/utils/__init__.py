"""
Utility modules for FirmSight.
"""
from .logger import setup_logger
from .mock_firmware import create_mock_firmware

__all__ = ["setup_logger", "create_mock_firmware"]
