import os
import logging
from src.response import synthesize_dns_response  # Optional, if used for export

# =======================
# Project Paths & Storage
# =======================
PROJECT_PATH = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OS_RECORD_PATH = os.path.join(PROJECT_PATH, "os_record")
os.makedirs(OS_RECORD_PATH, exist_ok=True)

AUTO_LEARN_MISSING = True

# =======================
# Protocol Header Lengths
# =======================
ETH_HEADER_LEN = 14
IP_HEADER_LEN = 20
ARP_HEADER_LEN = 28
TCP_HEADER_LEN = 20
UDP_HEADER_LEN = 8
ICMP_HEADER_LEN = 8

L3_PROC = ['ip', 'arp']
L4_PROC = ['tcp', 'udp', 'icmp']

# =======================
# Custom Rules (Layer 3/4)
# =======================
CUSTOM_RULES = [
    {
        "proto": "TCP", "port": 80, "flags": "S", "action": "drop",
        "log": "🔒 Dropping TCP SYN to port 80"
    },
    {
        "proto": "UDP", "port": 53, "action": "icmp_unreachable",
        "log": "📋 Faking ICMP Unreachable for UDP 53"
    },
    {
        "proto": "ICMP", "type": 8, "action": "template",
        "log": "💬 Handling ICMP Echo using template"
    }
]

# =======================
# TLS/JA3 Rules
# =======================
JA3_RULES = [
    {
        "ja3": "771,4865-4866-49195-49196,0-11-10,29-23-24,0",
        "action": "template",
        "template_name": "ja3_tls_windows11",
        "log": "🎭 Routing Nmap TLS probe to JA3-Windows11 template"
    },
    {
        "ja3": "771,49195-49196-49199,0-10-11,23-24,0",
        "action": "drop",
        "log": "❌ Dropping suspicious JA3 fingerprint"
    }
]

# =======================
# Network Interfaces (manual or dynamic via CLI)
# =======================
NIC_TARGET = 'ens192'
NIC_PROBE  = 'ens224'

VLAN_TARGET = None
VLAN_PROBE = None

VLAN_MAP = {
    NIC_TARGET: VLAN_TARGET,
    NIC_PROBE: VLAN_PROBE,
}

GATEWAY_MAP = {
    NIC_TARGET: '192.168.23.1',
    NIC_PROBE: '192.168.10.1',
}

# =======================
# Interface Check Utils
# =======================
def check_nic_exists(nic: str) -> bool:
    return os.path.exists(f"/sys/class/net/{nic}")

def get_mac_address(nic: str) -> str:
    try:
        with open(f"/sys/class/net/{nic}/address", "r") as f:
            return f.read().strip()
    except Exception as e:
        raise RuntimeError(f"❌ Could not get MAC for {nic}: {e}")

# =======================
# Port Deception Defaults
# =======================
FREE_PORT = [4441, 5551, 6661]

# =======================
# OS Fingerprint Templates
# =======================
FALLBACK_TTL = 64
FALLBACK_WINDOW = 8192

BASE_OS_TEMPLATES = {
    "linux": {
        "ttl": 64, "window": 5840,
        "tcp_options": ["MSS=1460", "SACK", "TS", "NOP", "NOP"]
    },
    "win10": {
        "ttl": 128, "window": 8192,
        "ipid": "random", "tos": 0x02, "ecn": 0, "df": True,
        "tcp_reserved": 0, "ip_options": [],
        "tcp_options": ["MSS=1460", "SACK", "TS", "WS=7", "NOP", "NOP"]
    },
    "win11": {
        "ttl": 128, "window": 64240,
        "tcp_options": ["MSS=1460", "SACK", "TS", "WS=8", "NOP", "NOP"]
    },
    "windows2022": {
        "ttl": 128, "window": 65535,
        "tcp_options": ["MSS=1460", "SACK", "TS", "WS=8", "NOP", "NOP"]
    },
    "windows2025": {
        "ttl": 128, "window": 65535,
        "tcp_options": ["MSS=1460", "SACK", "TS", "WS=8", "NOP", "NOP"]
    },
    "mac": {
        "ttl": 64, "window": 65535,
        "ipid": "zero", "df": True,
        "tcp_options": ["MSS=1460", "SACK", "TS", "WS=6", "NOP", "NOP"]
    }
}

OS_ALIASES = {
    "windows10": "win10", "windows11": "win11",
    "windows2022": "windows2022", "windows2025": "windows2025",
    "ubuntu20": "linux", "macos": "mac"
}

def get_os_fingerprint(os_name: str) -> dict:
    name = os_name.lower()
    if name in OS_ALIASES:
        base = OS_ALIASES[name]
        logging.info(f"🧹 Resolved alias '{name}' → '{base}'")
        return BASE_OS_TEMPLATES[base]
    if name in BASE_OS_TEMPLATES:
        logging.info(f"🧹 Found base template for '{name}'")
        return BASE_OS_TEMPLATES[name]
    for base in BASE_OS_TEMPLATES:
        if name.startswith(base):
            logging.info(f"🔁 Inheriting from base template: '{base}'")
            return BASE_OS_TEMPLATES[base]
    logging.warning(f"⚠ Unknown OS '{name}', using fallback TTL/Window")
    return {"ttl": FALLBACK_TTL, "window": FALLBACK_WINDOW}

def list_all_templates() -> dict:
    all_keys = set(BASE_OS_TEMPLATES.keys()) | set(OS_ALIASES.keys())
    return {k: get_os_fingerprint(k) for k in sorted(all_keys)}

def print_interface_summary():
    for nic in [NIC_TARGET, NIC_PROBE]:
        try:
            mac = get_mac_address(nic)
            gw = GATEWAY_MAP.get(nic)
            vlan = VLAN_MAP.get(nic)
            logging.info(f"🔌 {nic}: MAC={mac}, GW={gw}, VLAN={vlan}")
        except Exception as e:
            logging.warning(f"⚠ Interface summary failed for {nic}: {e}")
