import os
import logging
import time
import random
import copy
from scapy.all import get_if_addr, get_if_hwaddr

# =======================
# Project Paths & Storage
# =======================
# Establishes the root directory and storage locations for logs and learned fingerprints [1].
PROJECT_PATH = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OS_RECORD_PATH = os.path.join(PROJECT_PATH, "os_record")
os.makedirs(OS_RECORD_PATH, exist_ok=True)

# Path configuration for the persistence engine cache profiles [1].
LEARNED_FINGERPRINTS_FILE = os.path.join(OS_RECORD_PATH, "learned_fingerprints.json")

# Backdate clock safely to provide accurate, multi-day uptime signatures [2].
START_TIME = time.time() - random.randint(86400, 2592000)

# =======================
# Toggle Settings
# =======================
# Enables the system to automatically register new fingerprint profiles during scans [2].
AUTO_LEARN_MISSING = True

# =======================
# Protocol Header Lengths
# =======================
# Standard RFC lengths for parsing and packet crafting [2].
ETH_HEADER_LEN = 14
IP_HEADER_LEN = 20
ARP_HEADER_LEN = 28
TCP_HEADER_LEN = 20
UDP_HEADER_LEN = 8
ICMP_HEADER_LEN = 8

L3_PROC = ['ip', 'arp']
L4_PROC = ['tcp', 'udp', 'icmp']

# =======================
# Deception Services Config
# =======================
# Defines banners used to mislead service version detection [3].
SERVICES = {
    "SSH": {"port": 22, "proto": "tcp", "banner": "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5"},
    "HTTP": {"port": 80, "proto": "tcp", "banner": "HTTP/1.1 200 OK\r\nServer: Apache/2.4.41\r\n\r\n"},
    "RDP": {"port": 3389, "proto": "tcp", "banner": None}, # Processed via low-level application layers [3].
}

# =======================
# Custom Rules (Layer 3/4)
# =======================
# Rules dictating how the toolkit responds to specific port probes [3, 4].
CUSTOM_RULES = [
    {
        "proto": "tcp", "port": 80, "flags": "S", "action": "drop",
        "log": "🔒 Dropping TCP SYN to port 80"
    },
    {
        "proto": "udp", "port": 53, "action": "icmp_unreachable",
        "log": "📋 Faking ICMP Unreachable for UDP 53"
    }
]

# =======================
# TLS/JA3 Rules
# =======================
# Rules for matching specific TLS fingerprints to deception templates [4].
JA3_RULES = [
    {
        "ja3": "771,4865-4866-49195-49196,0-11-10,29-23-24,0",
        "action": "template",
        "template_name": "ja3_tls_windows11",
        "log": "🎭 Routing Nmap TLS probe to JA3-Windows11 template"
    }
]

# =======================
# Network Interfaces
# =======================
# Dual-NIC configuration for bridging/intercepting traffic [5].
NIC_TARGET = 'ens192' # Interface connected to the actual server
NIC_PROBE  = 'ens224' # Interface connected to the scanner/attacker

# VLAN Tagging configuration [5].
VLAN_MAP = {
    NIC_TARGET: None,
    NIC_PROBE: None,
}

# Gateway Mapping for routing deceptive replies [5].
GATEWAY_MAP = {
    NIC_TARGET: '192.168.23.1',
    NIC_PROBE: '192.168.10.1',
}

# =======================
# Port Deception Defaults
# =======================
DECEPTION_PORTS = 

# =======================
# OS Fingerprint Templates (Advanced)
# =======================
# Baseline network signatures for various operating systems [5-7].
FALLBACK_TTL = 64
FALLBACK_WINDOW = 8192

BASE_OS_TEMPLATES = {
    "linux": {
        "ttl": 64, "window": 5840, "df": True,
        "tcp_options": [('MSS', 1460), ('SAckOK', b''), ('NOP', b''), ('Timestamp', (0, 0)), ('WScale', 7)]
    },
    "win10": {
        "ttl": 128, "window": 8192, "df": True,
        "tcp_options": [('MSS', 1460), ('SAckOK', b''), ('NOP', b''), ('Timestamp', (0, 0)), ('WScale', 2)]
    },
    "win_legacy": {
        "ttl": 128, "window": 65535, "df": True,
        "tcp_options": [('MSS', 1460), ('NOP', b''), ('NOP', b''), ('SAckOK', b'')]
    },
    "linux_legacy": {
        "ttl": 64, "window": 32120, "df": True,
        "tcp_options": [('MSS', 1460), ('SAckOK', b''), ('NOP', b''), ('WScale', 6)]
    }
}

OS_ALIASES = {
    "windows10": "win10",
    "ubuntu": "linux"
}

# =======================
# Heuristic Rules for Auto-Learning
# =======================
# Logic for classifying unknown fingerprints based on observed metrics [7, 8].
HEURISTIC_RULES = [
    {
        "name": "win10",
        "match": lambda window, ttl, opts: 8000 <= window <= 65535 and ttl > 100
    },
    {
        "name": "linux",
        "match": lambda window, ttl, opts: window < 8000 and ttl <= 64
    }
]

def get_os_fingerprint(os_name: str, packet_features: dict = None) -> dict:
    """
    Retrieves platform fingerprints dynamically, applying heuristics for unknown profiles [8, 9].
    """
    name = os_name.lower()
    is_learned_unknown = name.startswith("unknown_learned")
    resolved_name = "heuristic_match" if is_learned_unknown else OS_ALIASES.get(name, name)

    if resolved_name == "heuristic_match" and packet_features:
        logging.info("🧠 Applying fingerprint heuristics rules over unmapped host profile...")
        for rule in HEURISTIC_RULES:
            if rule["match"](packet_features.get('window', 0),
                           packet_features.get('ttl', 0),
                           packet_features.get('options', [])):
                resolved_name = rule["name"]
                logging.info(f"💡 Heuristics matching success: {resolved_name}")
                break

    if resolved_name == "heuristic_match":
        resolved_name = "linux" # Default fallback [10].

    if resolved_name in BASE_OS_TEMPLATES:
        logging.info(f"🧹 Resolved fingerprint alias profile target: '{os_name}' → '{resolved_name}'")
        template = copy.deepcopy(BASE_OS_TEMPLATES[resolved_name])
        
        # Calculate precise TCP timestamps (represented in milliseconds) [11].
        current_ts = int((time.time() - START_TIME) * 1000)
        new_options = []
        for opt in template["tcp_options"]:
            if opt == 'Timestamp':
                new_options.append(('Timestamp', (current_ts, 0)))
            else:
                new_options.append(opt)
        template["tcp_options"] = new_options
        return template

    logging.warning(f"⚠ Target environment profile lookup failed for '{name}'. Utilizing global default configurations.")
    return {"ttl": FALLBACK_TTL, "window": FALLBACK_WINDOW, "tcp_options": []}

def get_mac_address(nic: str) -> str:
    """
    Safely retrieves the hardware MAC address of a specified interface [12].
    """
    try:
        return get_if_hwaddr(nic)
    except Exception as e:
        logging.error(f"❌ Custom Driver Framework Error: Failed to extract MAC address configuration on device interface {nic}: {e}")
        return "00:00:00:00:00:00"
