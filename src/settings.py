import os
import getpass
import socket

# 🔹 Auto-detect user and project paths
CC_USER = getpass.getuser()
CC_HOME = os.path.expanduser("~")
PROJECT_PATH = os.path.join(CC_HOME, "Camouflage-Cloak")
OS_RECORD_PATH = os.path.join(PROJECT_PATH, "os_record")

# 🔹 Ensure OS record directory exists
os.makedirs(OS_RECORD_PATH, exist_ok=True)

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

# 🔹 NIC Definitions
# Interface facing the TARGET (e.g., real device being deceived)
NIC_TARGET = "ens192"  # Change if needed

# Interface facing the ATTACKER (e.g., Nmap scanner)
NIC_ATTACKER = "ens224"  # Change if needed

# 🔹 Host deception IP (Camouflage Cloak IP)
HOST = "192.168.23.206"  # This IP must match the NIC_TARGET IP

# 🔹 Function to retrieve MAC address from interface
def get_mac_address(nic: str) -> str:
    try:
        with open(f"/sys/class/net/{nic}/address", "r") as f:
            return f.read().strip()
    except FileNotFoundError:
        raise ValueError(f"❌ Network interface {nic} not found.")
    except Exception as e:
        raise RuntimeError(f"❌ Error retrieving MAC address: {e}")

# 🔹 NIC Existence Validation
def check_nic_exists(nic: str) -> bool:
    return os.path.exists(f"/sys/class/net/{nic}")

# 🔹 Validate and retrieve MAC for TARGET NIC
if not check_nic_exists(NIC_TARGET):
    raise ValueError(f"❌ Target NIC {NIC_TARGET} not found!")
MAC = get_mac_address(NIC_TARGET)

# 🔹 Free ports for OS deception (used in TCP filtering)
FREE_PORT = [4441, 5551, 6661]
