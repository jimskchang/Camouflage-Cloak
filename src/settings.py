"""
=============================================
Camouflage Cloak Configuration - settings.py
=============================================

This script contains configurations for the Camouflage Cloak system, including:
- Network settings (Manual Input Required)
- NIC & MAC configurations for all hosts (Manual Input Required)
- Logging & Output Directory Management
- Support for running `--scan ts` via Python

## Installation & Setup Instructions:

### Manually Edit `settings.py`
Set the correct **IP addresses, NICs, and MACs** based on your environment.
"""

import os

# ========================
# ✅ REQUIRED NETWORK SETTINGS
# ========================

# Default NIC (Can be overridden by CLI argument)
CLOAK_NIC = "ens192"  # Change dynamically in `main.py` if needed

# Cloak Host (This machine)
CLOAK_HOST = "192.168.23.206"
CLOAK_MAC = "00:50:56:8E:35:6F"

# Target Server (Target Host)
TARGET_SERVER_NIC = "ens192"
TARGET_SERVER = "192.168.23.200"
TARGET_SERVER_MAC = "00:50:56:8E:4B:2B"

# OS Type for Target Server (Modify accordingly: "win10", "win7", "linux", etc.)
TARGET_SERVER_OS = "win10"

# ========================
# ✅ OUTPUT DIRECTORY SETTINGS
# ========================

# Default base directory for OS record storage (Overridden by CLI argument)
BASE_OS_RECORD_DIR = os.path.join(os.getcwd(), "os_records")

# Function to ensure directory exists dynamically
def get_os_record_dir(custom_path=None):
    os_record_dir = custom_path if custom_path else BASE_OS_RECORD_DIR
    os.makedirs(os_record_dir, exist_ok=True)
    return os_record_dir

# ========================
# ✅ PACKET SETTINGS
# ========================

# Ethernet header length
ETH_HEADER_LEN = 14

# IP header length (without options)
IP_HEADER_LEN = 20

# TCP header length (without options)
TCP_HEADER_LEN = 20

# Other Protocol Headers
ARP_HEADER_LEN = 28
UDP_HEADER_LEN = 8
ICMP_HEADER_LEN = 8

# Layer 3 & Layer 4 Processing Protocols
L3_PROC = ['ip', 'arp']
L4_PROC = ['tcp', 'udp', 'icmp']
