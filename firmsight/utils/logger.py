"""
Centralized logging for FirmSight
"""

import logging
import sys
from rich.logging import RichHandler

def setup_logger(name: str = "firmsight", level: int = logging.INFO) -> logging.Logger:
    """Configures a rich console logger."""
    logger = logging.getLogger(name)
    logger.setLevel(level)

    if not logger.handlers:
        handler = RichHandler(
            rich_tracebacks=True,
            show_time=True,
            show_level=True,
            show_path=False,
        )
        formatter = logging.Formatter("%(message)s")
        handler.setFormatter(formatter)
        logger.addHandler(handler)

    return logger
