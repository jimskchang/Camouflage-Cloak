import os
import subprocess
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s]: %(message)s")

# Global Constants
ETH_HEADER_LEN = 14
IP_HEADER_LEN = 20
ARP_HEADER_LEN = 28
TCP_HEADER_LEN = 20
UDP_HEADER_LEN = 8
ICMP_HEADER_LEN = 8
L3_PROC = ['ip', 'arp']
L4_PROC = ['tcp', 'udp', 'icmp']

# Camouflage-Cloak Server Setting
HOST = '192.168.23.206'  # Replace based on your Camouflage-Cloak Server IP
NIC = 'ens192'  # Replace based on your Camouflage-Cloak Server NIC

# Validate NIC before setting address path
NICAddr = f"/sys/class/net/{NIC}/address"
if not os.path.exists(NICAddr):
    logging.error(f"NIC {NIC} does not exist. Check network interface.")
    NICAddr = None  # Avoid using an invalid NIC path

record_path = 'pkt_record.txt'

# Get MAC dynamically
try:
    import netifaces
    mac = netifaces.ifaddresses(NIC)[netifaces.AF_LINK][0]['addr']
except Exception as e:
    logging.error(f"Failed to fetch MAC address: {e}")
    mac = b'\x00\x50\x56\x8e\x35\x6f'  # Fallback
