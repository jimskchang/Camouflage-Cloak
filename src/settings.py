# =============================================
# 📌 Global Constants for Packet Processing
# =============================================
import datetime
from pathlib import Path

# Layer 2 (Ethernet) Header Length
ETH_HEADER_LEN = 14

# Layer 3 (IP & ARP) Header Length
IP_HEADER_LEN = 20
ARP_HEADER_LEN = 28

# Layer 4 (Transport) Header Length
TCP_HEADER_LEN = 20
UDP_HEADER_LEN = 8
ICMP_HEADER_LEN = 8

# Supported Protocols
L3_PROC = ['ip', 'arp']
L4_PROC = ['tcp', 'udp', 'icmp']

# =============================================
# 📌 Network Interface & Host Configuration
# =============================================
HOST = '192.168.23.201'  # Target Host IP

# Network Interface (Change based on your setup)
NIC = 'ens192'
NIC_ADDR_PATH = f'/sys/class/net/{NIC}/address'  # Path to retrieve MAC address

# Packet Recording
RECORD_PATH = Path("pkt_record.txt")  # Use Pathlib for better file handling

# MAC Address (Use dynamic retrieval instead of hardcoded value)
try:
    with open(NIC_ADDR_PATH, "r") as mac_file:
        MAC_ADDRESS = bytes.fromhex(mac_file.read().strip().replace(":", ""))
except FileNotFoundError:
    MAC_ADDRESS = b'\x00\x50\x56\xb0\x10\xe9'  # Default MAC Address (Fallback)
except ValueError:
    MAC_ADDRESS = b'\x00\x00\x00\x00\x00\x00'  # Invalid MAC, use null
