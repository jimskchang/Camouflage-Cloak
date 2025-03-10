import os
import socket

# 🔹 User Credentials for Camouflage Cloak Server
CC_USER = "user"  # Change to your actual username
CC_PASS = "1qaz!QAZ"  # Change to Camouflage Cloak Server password

# 🔹 Ensure all files are stored in the user's home directory
CC_HOME = f"/home/{CC_USER}/Camouflage-Cloak"

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

# 🔹 Ensure fingerprint files & OS records are saved under user, not root
OS_RECORD_PATH = os.path.join(CC_HOME, "os_record")

# Manually Input: Set the correct network interface
NIC = 'ens192'
NIC_ADDR_PATH = f'/sys/class/net/{NIC}/address'

# Manually Set Host IP
HOST = "192.168.1.100"  # Change to the actual Camouflage Cloak Host IP

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
