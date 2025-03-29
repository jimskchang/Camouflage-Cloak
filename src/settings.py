import os
import socket
import logging

# =======================
# Project Paths & Storage
# =======================

# 🔹 Dynamically resolve the base project path
PROJECT_PATH = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OS_RECORD_PATH = os.path.join(PROJECT_PATH, "os_record")
os.makedirs(OS_RECORD_PATH, exist_ok=True)

# =======================
# Protocol Header Lengths
# =======================

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

# Optional: VLAN-aware interface mapping (used for packet parsing/logging)
VLAN_MAP = {
    NIC_TARGET: VLAN_TARGET,
    NIC_PROBE: VLAN_PROBE,
}

# Optional: gateway routing table (future use for routing or forwarding)
GATEWAY_MAP = {
    NIC_TARGET: GW_TARGET,
    NIC_PROBE: GW_PROBE,
}

# =======================
# NIC Validation & MAC Utils
# =======================

def check_nic_exists(nic: str) -> bool:
    return os.path.exists(f"/sys/class/net/{nic}")

if not check_nic_exists(NIC_TARGET):
    logging.warning(f"⚠ NIC_TARGET '{NIC_TARGET}' not found!")
if not check_nic_exists(NIC_PROBE):
    logging.warning(f"⚠ NIC_PROBE '{NIC_PROBE}' not found!")

def get_mac_address(nic: str) -> str:
    try:
        with open(f"/sys/class/net/{nic}/address", "r") as f:
            return f.read().strip()
    except FileNotFoundError:
        raise ValueError(f"❌ Error: Network interface '{nic}' not found!")
    except Exception as e:
        raise RuntimeError(f"❌ Unexpected error retrieving MAC address: {e}")

# Default MAC (used by some modules at init)
MAC = get_mac_address(NIC_TARGET)

# =======================
# Port Deception Settings
# =======================

# Define deceptive "free" TCP ports
FREE_PORT = [4441, 5551, 6661]

# =======================
# OS Fingerprint Templates
# =======================

BASE_OS_TEMPLATES = {
    "linux":        {"ttl": 64,  "window": 5840},
    "linux5":       {"ttl": 64,  "window": 29200},
    "centos":       {"ttl": 64,  "window": 5840},
    "mac":          {"ttl": 64,  "window": 65535},
    "freebsd":      {"ttl": 64,  "window": 65535},
    "win7":         {"ttl": 128, "window": 8192},
    "win10":        {"ttl": 128, "window": 65535},
    "win11":        {"ttl": 128, "window": 64240},
    "windows2022":  {"ttl": 128, "window": 65535},
    "windows2025":  {"ttl": 128, "window": 65535},
}

# 🔄 OS aliases (user-friendly names → real keys)
OS_ALIASES = {
    "windows10": "win10",
    "windows11": "win11",
    "windows7": "win7",
    "ubuntu20": "linux",
    "ubuntu22": "linux5",
    "centos7": "centos",
    "centos8": "centos",
    "macos": "mac",
    "macos12": "mac",
    "macos13": "mac",
}

def get_os_fingerprint(os_name: str) -> dict:
    name = os_name.lower()

    # Check alias mapping
    if name in OS_ALIASES:
        base = OS_ALIASES[name]
        return BASE_OS_TEMPLATES[base]

    # Direct match
    if name in BASE_OS_TEMPLATES:
        return BASE_OS_TEMPLATES[name]

    # Match by OS family prefix (e.g., win10_22h2 → win10)
    for base in BASE_OS_TEMPLATES:
        if name.startswith(base):
            logging.info(f"🔁 Detected OS version '{name}', inheriting base template '{base}'")
            return BASE_OS_TEMPLATES[base]

    # Fallback default
    logging.warning(f"⚠ Unknown OS '{name}', using fallback TTL/Window")
    return {"ttl": 64, "window": 8192}
