import os
import socket
import getpass  # Auto-detects the user running the script

# 🔹 Automatically detect the correct user and home directory
CC_USER = getpass.getuser()
CC_HOME = os.path.expanduser("~")

# 🔹 Ensure Camouflage Cloak stores fingerprints under the user directory
PROJECT_PATH = os.path.join(CC_HOME, "Camouflage-Cloak")
OS_RECORD_PATH = os.path.join(PROJECT_PATH, "os_record")

# Ensure the OS record directory exists
if not os.path.exists(OS_RECORD_PATH):
    os.makedirs(OS_RECORD_PATH, exist_ok=True)

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

# Set correct network interfaces
NIC_TARGET = 'ens192'  # NIC facing the target host
NIC_PROBE = 'ens224'   # NIC facing the scanning attacker
NIC_ADDR_PATH = f'/sys/class/net/{NIC_TARGET}/address'

# 🔹 Set Camouflage Cloak IP (the actual IP address of the cloak server, not the target)
HOST = "192.168.23.206"  # This must match the IP address of the NIC connected to the network

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

# Retrieve MAC Address for target NIC
MAC = get_mac_address(NIC_TARGET)

# Validate NIC Existence
def check_nic_exists(nic: str) -> bool:
    """Check if the specified network interface exists."""
    return os.path.exists(f"/sys/class/net/{nic}")

if not check_nic_exists(NIC_TARGET):
    raise ValueError(f"Error: Network interface {NIC_TARGET} not found!")

# FREE PORT
FREE_PORT = [4441, 5551, 6661]  # Ports considered 'free' for deception
