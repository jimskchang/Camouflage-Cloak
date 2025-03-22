import os
import socket
import getpass  # Auto-detects the user running the script

# 🔹 Automatically detect the current user and home directory
CC_USER = getpass.getuser()
CC_HOME = os.path.expanduser("~")

# 🔹 Camouflage Cloak project directory
PROJECT_PATH = os.path.join(CC_HOME, "Camouflage-Cloak")
OS_RECORD_PATH = os.path.join(PROJECT_PATH, "os_record")

# 🔹 Ensure fingerprint storage directory exists
os.makedirs(OS_RECORD_PATH, exist_ok=True)

# 🔹 Header lengths
ETH_HEADER_LEN = 14
IP_HEADER_LEN = 20
ARP_HEADER_LEN = 28
TCP_HEADER_LEN = 20
UDP_HEADER_LEN = 8
ICMP_HEADER_LEN = 8

# 🔹 Supported protocols
L3_PROC = ['ip', 'arp']
L4_PROC = ['tcp', 'udp', 'icmp']

# 🔹 Network interface roles (update these manually as needed)
NIC_TARGET = 'ens192'  # NIC connected to the target host
NIC_PROBE  = 'ens224'  # NIC exposed to scanning attacker (Nmap, etc.)

# 🔹 Camouflage Cloak host IP (must match NIC_TARGET IP)
HOST = "192.168.23.206"

# 🔹 Get MAC address for NIC_TARGET (used for ARP spoofing)
def get_mac_address(nic: str) -> str:
    try:
        with open(f"/sys/class/net/{nic}/address", "r") as f:
            return f.read().strip()
    except FileNotFoundError:
        raise ValueError(f"❌ Error: Network interface '{nic}' not found!")
    except Exception as e:
        raise RuntimeError(f"❌ Unexpected error retrieving MAC address for {nic}: {e}")

# MAC for NIC_TARGET (used throughout deception logic)
MAC = get_mac_address(NIC_TARGET)

# 🔹 Validate NICs
def check_nic_exists(nic: str) -> bool:
    return os.path.exists(f"/sys/class/net/{nic}")

if not check_nic_exists(NIC_TARGET):
    raise ValueError(f"❌ Error: NIC_TARGET '{NIC_TARGET}' not found!")
if not check_nic_exists(NIC_PROBE):
    raise ValueError(f"❌ Error: NIC_PROBE '{NIC_PROBE}' not found!")

# 🔹 List of ports to ignore for deception (free ports)
FREE_PORT = [4441, 5551, 6661]
