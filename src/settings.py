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

# 🔹 Manually defined network interfaces
NIC_TARGET = 'ens192'  # NIC connected to the target host
NIC_PROBE  = 'ens224'  # NIC exposed to scanning attacker (Nmap, etc.)

# 🔹 IP of Camouflage Cloak device (should match NIC_TARGET IP)
HOST = "192.168.23.206"

# 🔹 MAC address of NIC_TARGET (used in ARP response spoofing)
def get_mac_address(nic: str) -> str:
    try:
        with open(f"/sys/class/net/{nic}/address", "r") as f:
            return f.read().strip()
    except FileNotFoundError:
        raise ValueError(f"❌ Error: Network interface '{nic}' not found!")
    except Exception as e:
        raise RuntimeError(f"❌ Unexpected error retrieving MAC address: {e}")

MAC = get_mac_address(NIC_TARGET)

# 🔹 Interface validation logic
def check_nic_exists(nic: str) -> bool:
    return os.path.exists(f"/sys/class/net/{nic}")

if not check_nic_exists(NIC_TARGET):
    raise ValueError(f"❌ Error: NIC_TARGET '{NIC_TARGET}' not found!")
if not check_nic_exists(NIC_PROBE):
    raise ValueError(f"❌ Error: NIC_PROBE '{NIC_PROBE}' not found!")

# 🔹 Define which TCP ports should be ignored as "free"
FREE_PORT = [4441, 5551, 6661]

# 🔹 OS Fingerprint Presets (TTL + TCP Window Sizes)
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
    """Return TTL and TCP window size for a given OS name."""
    return OS_TEMPLATES.get(os_name.lower(), {"ttl": 64, "window": 8192})
