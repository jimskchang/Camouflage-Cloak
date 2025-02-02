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

# Import key modules for global access
try:
    from . import settings  # Ensure settings.py exists in the same package
except ImportError as e:
    logging.error(f"Failed to import settings: {e}")
    raise

# Import other key modules
from .Packet import Packet
from .tcp import TcpConnect
from .os_deceiver import OsDeceiver
from .port_deceiver import PortDeceiver
from .utils import (
    calculate_checksum,
    generate_random_mac,
    generate_random_ip,
    convert_mac_to_bytes,
    convert_ip_to_bytes,
    convert_bytes_to_mac,
    convert_bytes_to_ip
)

logging.info("Camouflage Cloak Package Initialized")
