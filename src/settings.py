# NOTE: Global Constants
import socket
import os

# Header Lengths
ETH_HEADER_LEN = 14
IP_HEADER_LEN = 20
ARP_HEADER_LEN = 28
TCP_HEADER_LEN = 20
UDP_HEADER_LEN = 8
ICMP_HEADER_LEN = 8

# Supported Protocols
L3_PROC = ['ip', 'arp']
L4_PROC = ['tcp', 'udp', 'icmp']

# NOTE: Network Settings
# Manually Input: Set the correct network interface
NIC = 'ens192'  # Change to the correct network interface
NIC_ADDR_PATH = f'/sys/class/net/{NIC}/address'
RECORD_PATH = 'pkt_record.txt'

# Manually Set Host IP
# Manually Input: Set the Camouflage Cloak Host IP
HOST = "192.168.1.100"  # Replace with the actual Camouflage Cloak Host IP

# Function to Get MAC Address
def get_mac_address(nic: str) -> str:
    """Retrieve the MAC address of the given network interface."""
    try:
        with open(f"/sys/class/net/{nic}/address", "r") as f:
            return f.read().strip()
    except FileNotFoundError:
        raise ValueError(f"Error: Network interface {nic} not found!")
    except Exception as e:
        raise RuntimeError(f"Unexpected error retrieving MAC address: {e}")

# Retrieve MAC Address
MAC = get_mac_address(NIC)

# Validate NIC Existence
def check_nic_exists(nic: str) -> bool:
    """Check if the specified network interface exists."""
    return os.path.exists(f"/sys/class/net/{nic}")

if not check_nic_exists(NIC):
    raise ValueError(f"Error: Network interface {NIC} not found!")
