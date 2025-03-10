import os
import socket
import getpass  # ✅ Auto-detects the user running the script

# 🔹 Get the Username Running the Script
CC_USER = getpass.getuser()  # Automatically gets the username
CC_HOME = f"/home/{CC_USER}/Camouflage-Cloak"  # Uses the correct user home directory

# 🔹 Always store OS fingerprints under user, not root
OS_RECORD_PATH = os.path.join(CC_HOME, "os_record")

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

# Set correct network interface
NIC = 'ens192'
NIC_ADDR_PATH = f'/sys/class/net/{NIC}/address'

# Set Host IP
HOST = "192.168.1.100"

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
