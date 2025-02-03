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

# Cloak Host (This machine)
CLOAK_NIC = "ens192"   # Network Interface Card
CLOAK_HOST = "192.168.23.206"
CLOAK_MAC = "00:50:56:8E:35:6F"

# Target Host (Attacker or Scanner)
TARGET_NIC = "ens192"
TARGET_HOST = "192.168.23.202"
TARGET_MAC = "00:50:56:8E:4D:0F"

# TS Server (Deception Target)
TS_SERVER_NIC = "ens192"
TS_SERVER = "192.168.23.200"
TS_SERVER_MAC = "00:0C:29:1E:77:FD"

# OS Type for TS Server (Modify accordingly: "win10", "win7", "linux", etc.)
TS_SERVER_OS = "win10"

# ========================
# ✅ OUTPUT DIRECTORY SETTINGS
# ========================

# Default output directory for storing deception logs
TS_OS_OUTPUT_DIR = os.path.join(os.getcwd(), "output")

# Ensure the directory exists
os.makedirs(TS_OS_OUTPUT_DIR, exist_ok=True)

# ========================
# ✅ PACKET SETTINGS
# ========================

# Ethernet header length
ETH_HEADER_LEN = 14

# IP header length (without options)
IP_HEADER_LEN = 20

# TCP header length (without options)
TCP_HEADER_LEN = 20
