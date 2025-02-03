"""
==========================================
Camouflage Cloak Package Initialization
==========================================

This file makes `src/` a valid Python package and initializes key settings.
"""

import logging

# Configure logging at the package level
logging.basicConfig(
    format="%(asctime)s [%(levelname)s]: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    level=logging.INFO
)

# Ensure settings module is available
try:
    from . import settings
except ImportError as e:
    logging.error(f"Failed to import settings: {e}")
    raise

# Import core modules safely
try:
    from .Packet import Packet
    from .tcp import TcpConnect
    from .os_deceiver import OsDeceiver
    from .port_deceiver import PortDeceiver
    from . import utils  # Import entire utils module instead of specific functions
except ImportError as e:
    logging.error(f"Error importing core modules: {e}")
    raise

logging.info("Camouflage Cloak Package Initialized")
