import os
import socket
import getpass  # Auto-detects the user running the script

# 🔹 Automatically detect the correct user and home directory
CC_USER = getpass.getuser()
CC_HOME = os.path.expanduser("~")

# 🔹 Camouflage Cloak project directories
PROJECT_PATH = os.path.join(CC_HOME, "Camouflage-Cloak")
OS_RECORD_PATH = os.path.join(PROJECT_PATH, "os_record")

# Ensure fingerprint storage directory exists
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

# 🔹 Define network interface roles (manually configured)
NIC_TARGET = 'ens192'  # 🔹 NIC connected to the target host
NIC_PROBE  = 'ens224'  # 🔹 NIC exposed to the scanning attacker (Nmap, etc.)

# 🔹 Set the Camouflage Cloak server's IP address (must match NIC_TARGET IP)
HOST = "192.168.23.206"

# 🔹 MAC address of NIC_TARGET
def get_mac_address(nic: str) -> str:
    try:
        with open(f"/sys/class/net/{nic}/address", "r") as f:
            return f.read().strip()
    except FileNotFoundError:
        raise ValueError(f"❌ Error: Network interface '{nic}' not found!")
    except Exception as e:
        raise RuntimeError(f"❌ Unexpected error retrieving MAC address: {e}")

MAC = get_mac_address(NIC_TARGET)

# 🔹 Verify NIC existence
def check_nic_exists(nic: str) -> bool:
    return os.path.exists(f"/sys/class/net/{nic}")

if not check_nic_exists(NIC_TARGET):
    raise ValueError(f"❌ Error: NIC_TARGET '{NIC_TARGET}' not found!")
if not check_nic_exists(NIC_PROBE):
    raise ValueError(f"❌ Error: NIC_PROBE '{NIC_PROBE}' not found!")

# 🔹 Define "free" ports to ignore for TCP deception
FREE_PORT = [4441, 5551, 6661]
