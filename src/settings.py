# NOTE: Global Constants
import socket
import os

ETH_HEADER_LEN = 14
IP_HEADER_LEN = 20
ARP_HEADER_LEN = 28
TCP_HEADER_LEN = 20
UDP_HEADER_LEN = 8
ICMP_HEADER_LEN = 8
L3_PROC = ['ip', 'arp']
L4_PROC = ['tcp', 'udp', 'icmp']

# NOTE: Settings
NIC = 'ens192'
NIC_ADDR_PATH = f'/sys/class/net/{NIC}/address'
RECORD_PATH = 'pkt_record.txt'

# Get Host IP Dynamically
HOST = socket.gethostbyname(socket.gethostname())

# Function to Get MAC Address
def get_mac_address(nic):
    try:
        with open(f"/sys/class/net/{nic}/address", "r") as f:
            return f.read().strip()
    except FileNotFoundError:
        return None  # Handle error if NIC does not exist

# Retrieve MAC Address
MAC = get_mac_address(NIC)

# Validate NIC Existence
def check_nic_exists(nic):
    return os.path.exists(f"/sys/class/net/{nic}")

if not check_nic_exists(NIC):
    raise ValueError(f"Error: Network interface {NIC} not found!")
