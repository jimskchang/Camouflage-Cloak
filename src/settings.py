"""
=============================================
Camouflage Cloak Configuration - settings.py
=============================================

# NOTE: Global Constants
import os
import datetime
import subprocess

ETH_HEADER_LEN = 14
IP_HEADER_LEN = 20
ARP_HEADER_LEN = 28
TCP_HEADER_LEN = 20
UDP_HEADER_LEN = 8
ICMP_HEADER_LEN = 8
L3_PROC = ['ip', 'arp']
L4_PROC = ['tcp', 'udp', 'icmp']

# NOTE: Network Configuration
host = '192.168.23.200'
NIC = 'ens192'

# Fetch MAC address dynamically for NIC
def get_mac_address(nic):
    try:
        return subprocess.check_output(["cat", f"/sys/class/net/{nic}/address"]).decode().strip()
    except Exception:
        return "Unknown"

NICAddr = get_mac_address(NIC)

# Default OS record output path
TARGET_OS_OUTPUT_DIR = os.path.join(os.getcwd(), "os_records")
os.makedirs(TARGET_OS_OUTPUT_DIR, exist_ok=True)  # Ensure the directory exists

# Record Path
record_path = 'pkt_record.txt'
mac = "00:0C:29:1E:77:FD"  # Updated to string format
