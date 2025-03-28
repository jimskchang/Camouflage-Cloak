import os
import socket
import getpass
import pwd

# 🔹 Always use the real user's home directory, even with sudo
CC_HOME = pwd.getpwuid(os.getuid()).pw_dir
CC_USER = getpass.getuser()

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

# Interface connected to the real target
NIC_TARGET = 'ens192'
IP_TARGET = '192.168.10.10'
GW_TARGET = '192.168.10.1'
VLAN_TARGET = None

# Interface facing the attacker/scanner
NIC_PROBE  = 'ens224'
IP_PROBE   = '192.168.23.206'
GW_PROBE   = '192.168.23.1'
VLAN_PROBE = None

# IP used to bind raw sockets (should be facing attacker)
HOST = IP_PROBE

# Optional: VLAN-aware interface mapping (useful for packet parsing/logging)
VLAN_MAP = {
    NIC_TARGET: VLAN_TARGET,
    NIC_PROBE: VLAN_PROBE,
}

# Optional: gateway routing table (future use for routing or forwarding)
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
    "linux": {"ttl": 64, "window": 5840},
    "linux5": {"ttl": 64, "window": 29200},
    "win7": {"ttl": 128, "window": 8192},
    "win10": {"ttl": 128, "window": 65535},
    "win11": {"ttl": 128, "window": 64240},
    "windows2022": {"ttl": 128, "window": 65535},
    "windows2025": {"ttl": 128, "window": 65535},
    "mac": {"ttl": 64, "window": 65535},
    "freebsd": {"ttl": 64, "window": 65535},
    "centos": {"ttl": 64, "window": 5840}
}

def get_os_fingerprint(os_name: str) -> dict:
    return OS_TEMPLATES.get(os_name.lower(), {"ttl": 64, "window": 8192})
