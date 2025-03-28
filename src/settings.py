import os
import socket
import getpass

# 🔹 Automatically detect the correct user and home directory
CC_USER = getpass.getuser()
CC_HOME = os.path.expanduser("~")

# 🔹 Project paths
PROJECT_PATH = os.path.join(CC_HOME, "Camouflage-Cloak")
OS_RECORD_PATH = os.path.join(PROJECT_PATH, "os_record")
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

# =======================
# Network Interface Setup
# =======================

NIC_TARGET = 'ens192'
IP_TARGET = '192.168.10.10'
GW_TARGET = '192.168.10.1'
VLAN_TARGET = None

NIC_PROBE  = 'ens224'
IP_PROBE   = '192.168.23.206'
GW_PROBE   = '192.168.23.1'
VLAN_PROBE = None

HOST = IP_PROBE

VLAN_MAP = {
    NIC_TARGET: None,
    NIC_PROBE: None,
}

GATEWAY_MAP = {
    NIC_TARGET: GW_TARGET,
    NIC_PROBE: GW_PROBE,
}

# 🔹 Get MAC from a specific NIC
def get_mac_address(nic: str) -> str:
    try:
        with open(f"/sys/class/net/{nic}/address", "r") as f:
            return f.read().strip()
    except FileNotFoundError:
        raise ValueError(f"❌ Error: Network interface '{nic}' not found!")
    except Exception as e:
        raise RuntimeError(f"❌ Unexpected error retrieving MAC address: {e}")

MAC = get_mac_address(NIC_TARGET)

# 🔹 Validate interfaces
def check_nic_exists(nic: str) -> bool:
    return os.path.exists(f"/sys/class/net/{nic}")

if not check_nic_exists(NIC_TARGET):
    raise ValueError(f"❌ Error: NIC_TARGET '{NIC_TARGET}' not found!")
if not check_nic_exists(NIC_PROBE):
    raise ValueError(f"❌ Error: NIC_PROBE '{NIC_PROBE}' not found!")

# 🔹 Define deceptive "free" TCP ports
FREE_PORT = [4441, 5551, 6661]

# =======================
# OS Fingerprint Templates
# =======================

OS_TEMPLATES = {
    "linux":        {"ttl": 64,  "window": 5840,  "ws": 2, "ip_id_mode": "increment"},
    "linux5":       {"ttl": 64,  "window": 29200, "ws": 1, "ip_id_mode": "increment"},
    "win7":         {"ttl": 128, "window": 8192,  "ws": 1, "ip_id_mode": "increment"},
    "win10":        {"ttl": 128, "window": 65535, "ws": 1, "ip_id_mode": "increment"},
    "win11":        {"ttl": 128, "window": 64240, "ws": 1, "ip_id_mode": "increment"},
    "windows2022":  {"ttl": 128, "window": 65535, "ws": 1, "ip_id_mode": "increment"},
    "windows2025":  {"ttl": 128, "window": 65535, "ws": 1, "ip_id_mode": "increment"},
    "mac":          {"ttl": 64,  "window": 65535, "ws": 3, "ip_id_mode": "random"},
    "freebsd":      {"ttl": 64,  "window": 65535, "ws": 3, "ip_id_mode": "random"},
    "centos":       {"ttl": 64,  "window": 5840,  "ws": 2, "ip_id_mode": "increment"},
    "openbsd":      {"ttl": 64,  "window": 16384, "ws": 0, "ip_id_mode": "zero"}
}

def get_os_fingerprint(os_name: str) -> dict:
    return OS_TEMPLATES.get(os_name.lower(), {"ttl": 64, "window": 8192, "ws": 0, "ip_id_mode": "random"})
