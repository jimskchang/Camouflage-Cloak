import os
import socket
import logging

# =======================
# Project Paths & Storage
# =======================

PROJECT_PATH = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OS_RECORD_PATH = os.path.join(PROJECT_PATH, "os_record")
os.makedirs(OS_RECORD_PATH, exist_ok=True)

AUTO_LEARN_MISSING = True  # Enable auto-learning of new probe templates

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

# ens192 = connected to Win10/Win11 hosts
NIC_TARGET = 'ens192'                    # used for --scan ts
IP_TARGET = '192.168.23.200'             # real Win10 for fingerprinting

# ens224 = connected to attacker (Nmap)
NIC_PROBE  = 'ens224'                    # used for --scan od
IP_PROBE   = '192.168.23.201'            # spoofed IP for deception (pretend to be Win11 as Win10)

GW_TARGET = '192.168.23.1'
GW_PROBE  = '192.168.10.1'

VLAN_TARGET = None
VLAN_PROBE = None

HOST = IP_PROBE

VLAN_MAP = {
    NIC_TARGET: VLAN_TARGET,
    NIC_PROBE: VLAN_PROBE,
}

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

MAC = get_mac_address(NIC_TARGET)

# =======================
# Port Deception Settings
# =======================

FREE_PORT = [4441, 5551, 6661]

# =======================
# OS Fingerprint Templates
# =======================

FALLBACK_TTL = 64
FALLBACK_WINDOW = 8192

BASE_OS_TEMPLATES = {
    "linux": {
        "ttl": 64,
        "window": 5840,
        "tcp_options": ["MSS=1460", "SACK", "TS", "NOP", "NOP"]
    },
    "linux5": {
        "ttl": 64,
        "window": 29200,
        "tcp_options": ["MSS=1460", "SACK", "TS", "WS=7", "NOP", "NOP"]
    },
    "centos": {
        "ttl": 64,
        "window": 5840,
        "tcp_options": ["MSS=1460", "SACK", "TS", "NOP", "NOP"]
    },
    "mac": {
        "ttl": 64,
        "window": 65535,
        "ipid": "zero",
        "df": True,
        "tcp_options": ["MSS=1460", "SACK", "TS", "WS=6", "NOP", "NOP"]
    },
    "freebsd": {
        "ttl": 64,
        "window": 65535,
        "tcp_options": ["MSS=1460", "SACK", "TS", "WS=5", "NOP", "NOP"]
    },
    "win7": {
        "ttl": 128,
        "window": 8192,
        "tcp_options": ["MSS=1460", "SACK", "TS", "WS=2", "NOP", "NOP"]
    },
    "win10": {
        "ttl": 128,
        "window": 8192,
        "ipid": "random",
        "tos": 0x02,
        "ecn": 0,
        "df": True,
        "tcp_reserved": 0,
        "ip_options": [],
        "tcp_options": ["MSS=1460", "SACK", "TS", "WS=7", "NOP", "NOP"]
    },
    "win11": {
        "ttl": 128,
        "window": 64240,
        "tcp_options": ["MSS=1460", "SACK", "TS", "WS=8", "NOP", "NOP"]
    },
    "windows2022": {
        "ttl": 128,
        "window": 65535,
        "tcp_options": ["MSS=1460", "SACK", "TS", "WS=8", "NOP", "NOP"]
    },
    "windows2025": {
        "ttl": 128,
        "window": 65535,
        "tcp_options": ["MSS=1460", "SACK", "TS", "WS=8", "NOP", "NOP"]
    },
}

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

    if name in OS_ALIASES:
        base = OS_ALIASES[name]
        result = BASE_OS_TEMPLATES[base]
        logging.info(f"🧩 Resolved alias '{name}' → '{base}'")
        return result

    if name in BASE_OS_TEMPLATES:
        result = BASE_OS_TEMPLATES[name]
        logging.info(f"🧩 Found base template for '{name}'")
        return result

    for base in BASE_OS_TEMPLATES:
        if name.startswith(base):
            result = BASE_OS_TEMPLATES[base]
            logging.info(f"🔁 Detected versioned OS '{name}', inheriting from base '{base}'")
            return result

    logging.warning(f"⚠ Unknown OS '{name}', using fallback TTL={FALLBACK_TTL}, Window={FALLBACK_WINDOW}")
    return {"ttl": FALLBACK_TTL, "window": FALLBACK_WINDOW}

def list_all_templates() -> dict:
    all_keys = set(BASE_OS_TEMPLATES.keys()) | set(OS_ALIASES.keys())
    return {k: get_os_fingerprint(k) for k in sorted(all_keys)}

def log_os_template(os_name: str):
    template = get_os_fingerprint(os_name)
    ttl = template.get("ttl")
    win = template.get("window")
    opts = template.get("tcp_options", [])
    logging.debug(f"🧬 OS Template '{os_name}' → TTL={ttl}, Window={win}, TCP_Options={opts}")
