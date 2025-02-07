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

# Target Server (Target Host)
TARGET_SERVER_NIC = "ens192"
TARGET_SERVER = "192.168.23.200"
TARGET_SERVER_MAC = "00:50:56:8E:4B:2B"

# OS Type for Target Server (Modify accordingly: "win10", "win7", "linux", etc.)
TARGET_SERVER_OS = "win10"  # ✅ Fixed Typo (was TASRGET_SERVER_OS)

# ========================
# ✅ OUTPUT DIRECTORY SETTINGS
# ========================

# Default output directory for storing OS deception logs
OS_RECORD_DIR = os.path.join(os.getcwd(), "os_records")

# Ensure the directory exists
os.makedirs(OS_RECORD_DIR, exist_ok=True)

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
