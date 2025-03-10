import os
import socket
import getpass  # ✅ Auto-detects the user running the script

# 🔹 Get the Username Running the Script (Ensures non-root execution)
CC_USER = getpass.getuser()
CC_HOME = f"/home/{CC_USER}/Camouflage-Cloak"  # Auto-detects correct user path

# 🔹 Always store OS fingerprints under user, not root
OS_RECORD_PATH = os.path.join(CC_HOME, "os_record")

# 🔹 Ensure the OS_RECORD_PATH exists
if not os.path.exists(OS_RECORD_PATH):
    os.makedirs(OS_RECORD_PATH, exist_ok=True)

# 🔹 Set Camouflage Cloak Server IP (NOT the target IP)
HOST = "192.168.23.206"  # This is the Camouflage-Cloak machine's IP

# 🔹 Header Lengths
ETH_HEADER_LEN = 14
IP_HEADER_LEN = 20
ARP_HEADER_LEN = 28
TCP_HEADER_LEN = 20
UDP_HEADER_LEN = 8
ICMP_HEADER_LEN = 8

# 🔹 Supported Protocols
L3_PROC = ['ip', 'arp']
L4_PROC = ['tcp', 'udp', 'icmp']

# 🔹 Set correct network interface
NIC = 'ens192'  # ⚠ Change to match your system's correct interface
NIC_ADDR_PATH = f'/sys/class/net/{NIC}/address'

# 🔹 Validate NIC Existence
def check_nic_exists(nic: str) -> bool:
    """Check if the specified network interface exists."""
    return os.path.exists(f"/sys/class/net/{nic}")

if not check_nic_exists(NIC):
    raise ValueError(f"❌ Error: Network interface {NIC} not found!")

# 🔹 Function to Get MAC Address
def get_mac_address(nic: str) -> str:
    """Retrieve the MAC address of the given network interface."""
    try:
        with open(f"/sys/class/net/{nic}/address", "r") as f:
            return f.read().strip()
    except FileNotFoundError:
        raise ValueError(f"❌ Error: Network interface {nic} not found!")
    except Exception as e:
        raise RuntimeError(f"❌ Unexpected error retrieving MAC address: {e}")

# 🔹 Retrieve MAC Address
MAC = get_mac_address(NIC)

# 🔹 Ensure Correct File & Folder Permissions
def ensure_correct_permissions(path: str):
    """Ensure correct read/write permissions for OS fingerprinting files."""
    try:
        if os.path.exists(path):
            os.chmod(path, 0o644)  # Read & Write for owner, Read for others
    except Exception as e:
        print(f"⚠ Warning: Failed to set permissions for {path}: {e}")

# 🔹 Ensure fingerprinting directory is accessible
ensure_correct_permissions(OS_RECORD_PATH)
