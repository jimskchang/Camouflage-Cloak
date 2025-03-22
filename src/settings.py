import os
import socket
import getpass  # ✅ Auto-detects the user running the script

# 🔹 Automatically detect the correct user and home directory
CC_USER = getpass.getuser()  # Detects the logged-in user
CC_HOME = os.path.expanduser("~")  # Expands to /home/user

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

# Set correct network interface
NIC = 'ens192'  # Change this if necessary
NIC_ADDR_PATH = f'/sys/class/net/{NIC}/address'

# 🔹 Set Camouflage-Cloak Host IP (This is NOT the target host, it's the Cloak server itself)
HOST = "192.168.23.206"  # ✅ Ensure this matches your actual Camouflage-Cloak server IP

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

# FREE PORT
FREE_PORT = [4441, 5551, 6661]  # or whatever ports are considered 'free' for deception
