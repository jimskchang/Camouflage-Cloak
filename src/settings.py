
=============================================
Camouflage Cloak Configuration - settings.py
=============================================

This script contains configurations for the Camouflage Cloak system, including:
- Network settings
- Target & Host OS settings
- TS (Template Synthesis) Server settings
- Logging & NIC detection
- Output directory handling

## Installation & Setup Instructions:

### 1️⃣ Linux / MacOS Setup:
   1. Ensure Python is installed (`python3 --version`).
   2. Install required dependencies:
      ```bash
      sudo apt update  # Ubuntu/Debian
      sudo yum update  # CentOS/RHEL
      ```
   3. Export environment variables (optional):
      ```bash
      export TARGET_HOST="192.168.1.150"
      export CLOAK_HOST="192.168.1.1"
      export TS_SERVER="192.168.1.200"
      export CLOAK_NIC="wlan0"
      ```
   4. Run your script:
      ```bash
      python3 script.py
      ```

### 2️⃣ Windows Setup:
   1. Install Python: Download from https://www.python.org/
   2. Open PowerShell or CMD as Administrator.
   3. Set environment variables (optional):
      ```powershell
      $env:TARGET_HOST="192.168.1.150"
      $env:CLOAK_HOST="192.168.1.1"
      $env:TS_SERVER="192.168.1.200"
      $env:CLOAK_NIC="Ethernet"
      ```
   4. Run the script:
      ```powershell
      python script.py
      ```

### 3️⃣ Docker Installation:
   1. Install Docker (https://docs.docker.com/get-docker/)
   2. Create a Docker container with Python:
      ```bash
      docker run --rm -it python:3.9 bash
      ```
   3. Copy `settings.py` into the container.
   4. Set environment variables and run the script inside the container.

For any issues, check logs in `/var/log/camouflage_cloak/cloak.log`
"""

import os
import logging
import subprocess
import platform

# NOTE: Global Constants
ETH_HEADER_LEN = 14
IP_HEADER_LEN = 20
ARP_HEADER_LEN = 28
TCP_HEADER_LEN = 20
UDP_HEADER_LEN = 8
ICMP_HEADER_LEN = 8
L3_PROC = ['ip', 'arp']
L4_PROC = ['tcp', 'udp', 'icmp']

# NOTE: Network Settings
DEFAULT_TARGET_HOST = "192.168.1.150"  # The machine being deceived
DEFAULT_CLOAK_HOST = "192.168.1.1"  # Your own Camouflage Cloak machine IP

# OS Settings
DEFAULT_TARGET_OS = "linux"  # Default target OS being cloaked
DEFAULT_CLOAK_OS = platform.system().lower()  # Detects the OS running the script

# TS Server Settings
DEFAULT_TS_SERVER = "192.168.1.200"  # Default TS server to be scanned for template synthesis

DEFAULT_OUTPUT_DIR = "/os_record"  # Base directory for storing records
TS_OUTPUT_DIR = os.path.join(DEFAULT_OUTPUT_DIR, "ts_server")  # Output directory for TS scan results

# MAC Addresses
DEFAULT_CLOAK_MAC = b'\x00\x50\x56\xb0\x10\xe9'  # MAC of the Cloak Host
DEFAULT_TARGET_MAC = b'\xaa\xbb\xcc\xdd\xee\xff'  # Default placeholder for Target MAC

# Load values from environment variables
TARGET_HOST = os.getenv("TARGET_HOST", DEFAULT_TARGET_HOST)  # The target being cloaked
CLOAK_HOST = os.getenv("CLOAK_HOST", DEFAULT_CLOAK_HOST)  # Camouflage Cloak host IP
TS_SERVER = os.getenv("TS_SERVER", DEFAULT_TS_SERVER)  # TS Server IP/Hostname

# Prompt user if TARGET_OS is not set
TARGET_OS = os.getenv("TARGET_OS")
if not TARGET_OS:
    TARGET_OS = input("Enter the Target Host OS (e.g., win10, win7, linux): ").strip().lower()
    if not TARGET_OS:
        TARGET_OS = DEFAULT_TARGET_OS  # Default fallback if user presses enter

# Define the OS of the cloak host (system running this script)
CLOAK_OS = os.getenv("CLOAK_OS", DEFAULT_CLOAK_OS).lower()

# Determine the full record path based on TARGET_OS
RECORD_DIR = os.path.join(DEFAULT_OUTPUT_DIR, TARGET_OS)
RECORD_PATH = os.path.join(RECORD_DIR, "pkt_record.txt")

# Ensure OS-specific and TS output directories exist
os.makedirs(RECORD_DIR, exist_ok=True)
os.makedirs(TS_OUTPUT_DIR, exist_ok=True)

# MAC Addresses (can be overridden via env vars)
CLOAK_MAC = bytes.fromhex(os.getenv("CLOAK_MAC", DEFAULT_CLOAK_MAC.hex()))
TARGET_MAC = bytes.fromhex(os.getenv("TARGET_MAC", DEFAULT_TARGET_MAC.hex()))

# Function to Detect Primary Network Interface
def detect_primary_nic():
    try:
        # Run ip route command to get the default NIC
        result = subprocess.run(["ip", "route", "show", "default"], capture_output=True, text=True, check=True)
        for line in result.stdout.splitlines():
            if "default via" in line:
                return line.split()[-1]  # Extract the NIC name
    except Exception as e:
        logging.error(f"Error detecting primary NIC: {e}")
    return "eth0"  # Fallback to eth0 if detection fails

# Dynamically determine NIC if not provided via env
NIC = os.getenv("CLOAK_NIC", detect_primary_nic())

# Dynamically resolve NIC address path
NICAddr = f"/sys/class/net/{NIC}/address"

# NOTE: Logging Configuration
DEFAULT_LOG_DIR = "/var/log/camouflage_cloak"
LOG_LEVEL = os.getenv("CLOAK_LOG_LEVEL", "DEBUG").upper()

# Ensure log directory exists
log_dir = os.getenv("CLOAK_LOG_DIR", DEFAULT_LOG_DIR)
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

# Configuration Validation
def validate_settings():
    """Validate essential settings and log warnings if needed."""
    if not TARGET_HOST:
        logging.warning("No target host specified, using default: %s", DEFAULT_TARGET_HOST)
    if not CLOAK_HOST:
        logging.warning("No Camouflage Cloak host specified, using default: %s", DEFAULT_CLOAK_HOST)
    
    if not TS_SERVER:
        logging.warning("No TS server specified, using default: %s", DEFAULT_TS_SERVER)
    else:
        logging.info(f"TS server to be scanned: {TS_SERVER}")

    if not NIC:
        logging.warning("No NIC specified, using auto-detected NIC: %s", detect_primary_nic())
    else:
        logging.info(f"Using network interface: {NIC}")

    logging.info(f"NIC in use: {NIC}")
    logging.info(f"TS scan output directory: {TS_OUTPUT_DIR}")

# Call validation at import
validate_settings()
