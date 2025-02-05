"""
==========================================
Camouflage Cloak Package Initialization
==========================================

This file makes `src/` a valid Python package and initializes key settings.
"""

import logging
import os
import sys

# Configure logging at the package level
logging.basicConfig(
    format="%(asctime)s [%(levelname)s]: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    level=logging.INFO
)

# Ensure `src/` is always in Python's module search path
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

# Ensure settings module is available
try:
    from . import settings

    # Validate essential settings to prevent runtime errors
    REQUIRED_SETTINGS = [
        "CLOAK_NIC", "CLOAK_HOST", "CLOAK_MAC",
        "TARGET_SERVER_NIC", "TARGET_SERVER", "TARGET_SERVER_MAC",
        "TARGET_SERVER_OS", "TARGET_OS_OUTPUT_DIR"
    ]
    
    for var in REQUIRED_SETTINGS:
        if not hasattr(settings, var):
            logging.error(f"Missing required setting: {var}. Please check settings.py")
            raise AttributeError(f"Missing required setting: {var}")

except ImportError as e:
    logging.error(f"Failed to import settings.py: {e}")
    raise ImportError("Critical Error: settings.py could not be loaded.")

# Import core modules safely
try:
    from .Packet import Packet
    from .tcp import TcpConnect
    from .os_deceiver import OsDeceiver
    from .port_deceiver import PortDeceiver
    from . import utils  # Import entire utils module instead of specific functions
except ImportError as e:
    logging.error(f"Error importing core modules: {e}")
    raise ImportError("Critical Error: Failed to load core modules.")

logging.info("Camouflage Cloak Package Initialized Successfully.")
