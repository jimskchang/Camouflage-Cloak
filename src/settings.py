
=============================================
Camouflage Cloak Configuration - settings.py
=============================================

This script contains configurations for the Camouflage Cloak system, including:
- Network settings (Manual Input Required)
- NIC & MAC configurations for all hosts (Manual Input Required)
- Logging & Output Directory Management
- Support for running `--scan ts` via Python

## Installation & Setup Instructions:

###  Manually edit `settings.py` (No auto-detection, all values must be set manually):
      ```python
      # REQUIRED: Cloak Host NIC (To be modified)
      CLOAK_NIC = "eth0"

      # REQUIRED: TS Server NIC (To be modified)
      TS_SERVER_NIC = "eth1"

      # REQUIRED: Target Host NIC (To be modified)
      TARGET_NIC = "eth2"

      # REQUIRED: Target Host IP (To be modified)
      TARGET_HOST = "192.168.1.150"

      # REQUIRED: Cloak Host IP (To be modified)
      CLOAK_HOST = "192.168.1.1"

      # REQUIRED: TS Server IP (To be modified)
      TS_SERVER = "192.168.1.200"

      # REQUIRED: Cloak Host MAC (To be modified)
      CLOAK_MAC = "00:50:56:b0:10:e9"

      # REQUIRED: TS Server MAC (To be modified)
      TS_SERVER_MAC = "00:AA:BB:CC:DD:EE"

      # REQUIRED: Target Host MAC (To be modified)
      TARGET_MAC = "00:11:22:33:44:55"
      ```
   4. Run your script:
      ```bash
      python3 script.py
      ```

For any issues, check logs in `/var/log/camouflage_cloak/cloak.log`


import datetime
import os
import logging

ETH_HEADER_LEN = 14
IP_HEADER_LEN = 20
ARP_HEADER_LEN = 28
TCP_HEADER_LEN = 20
UDP_HEADER_LEN = 8
ICMP_HEADER_LEN = 8
L3_PROC = ['ip', 'arp']
L4_PROC = ['tcp', 'udp', 'icmp']

# NOTE: Network Settings (Manual Input Required)
TARGET_HOST = "192.168.1.150"  # REQUIRED: Target Host IP (To be modified)
CLOAK_HOST = "192.168.1.1"  # REQUIRED: Cloak Host IP (To be modified)
TS_SERVER = "192.168.1.200"  # REQUIRED: TS Server IP (To be modified)

# NOTE: NIC Settings (Manual Input Required)
CLOAK_NIC = "eth0"  # REQUIRED: Cloak Host NIC (To be modified)
TS_SERVER_NIC = "eth1"  # REQUIRED: TS Server NIC (To be modified)
TARGET_NIC = "eth2"  # REQUIRED: Target Host NIC (To be modified)

# NOTE: MAC Addresses (Manual Input Required)
CLOAK_MAC = "00:50:56:b0:10:e9"  # REQUIRED: Cloak Host MAC (To be modified)
TS_SERVER_MAC = "00:AA:BB:CC:DD:EE"  # REQUIRED: TS Server MAC (To be modified)
TARGET_MAC = "00:11:22:33:44:55"  # REQUIRED: Target Host MAC (To be modified)

# NOTE: Output Directories
DEFAULT_OUTPUT_DIR = "/os_record"
TS_SERVER_OUTPUT_DIR = os.path.join(DEFAULT_OUTPUT_DIR, "ts_server")
TS_OS_OUTPUT_DIR = os.path.join(TS_SERVER_OUTPUT_DIR, "unknown")  # No auto-detected OS

# Ensure output directories exist
os.makedirs(TS_OS_OUTPUT_DIR, exist_ok=True)

# NOTE: Logging Configuration
DEFAULT_LOG_DIR = "/var/log/camouflage_cloak"
LOG_LEVEL = "DEBUG"

# Ensure log directory exists
log_dir = DEFAULT_LOG_DIR
os.makedirs(log_dir, exist_ok=True)

LOG_FILE = os.path.join(log_dir, "cloak.log")

logging.basicConfig(
    format="%(asctime)s [%(levelname)s]: %(message)s",
    datefmt="%y-%m-%d %H:%M",
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler()
    ]
)

# Function to Validate Required Manual Inputs
def validate_settings():
    """Ensure all required values are set manually."""
    required_vars = {
        "TARGET_HOST": TARGET_HOST,
        "CLOAK_HOST": CLOAK_HOST,
        "TS_SERVER": TS_SERVER,
        "CLOAK_NIC": CLOAK_NIC,
        "TS_SERVER_NIC": TS_SERVER_NIC,
        "TARGET_NIC": TARGET_NIC,
        "CLOAK_MAC": CLOAK_MAC,
        "TS_SERVER_MAC": TS_SERVER_MAC,
        "TARGET_MAC": TARGET_MAC
    }
    
    missing_vars = [var for var, value in required_vars.items() if not value]
    
    if missing_vars:
        raise ValueError(f"ERROR: The following settings are missing: {', '.join(missing_vars)}. Please update them manually in settings.py.")

    logging.info(f"✅ All required settings are properly configured.")

    logging.info(f"🌐 Cloak Host: {CLOAK_HOST} (NIC: {CLOAK_NIC}, MAC: {CLOAK_MAC})")
    logging.info(f"🌐 TS Server: {TS_SERVER} (NIC: {TS_SERVER_NIC}, MAC: {TS_SERVER_MAC})")
    logging.info(f"🌐 Target Host: {TARGET_HOST} (NIC: {TARGET_NIC}, MAC: {TARGET_MAC})")

    logging.info(f"📁 TS scan output directory: {TS_OS_OUTPUT_DIR}")

# Call validation at import
validate_settings()
