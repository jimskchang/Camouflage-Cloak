# settings.py — Camouflage Cloak Configuration

import os
import logging
import time # --- 新增：用於獲取時間 ---
from scapy.all import get_if_addr, get_if_hwaddr

# =======================
# Project Paths & Storage
# =======================
PROJECT_PATH = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OS_RECORD_PATH = os.path.join(PROJECT_PATH, "os_record")
os.makedirs(OS_RECORD_PATH, exist_ok=True)

# --- 新增：紀錄程式啟動時間（以秒為單位） ---
# 為了類比真實 uptime，這裡可以使用隨機時間減去，例如模擬啟動了 30 天
START_TIME = time.time() - random.randint(86400, 2592000)

# =======================
# Toggle Settings
# =======================
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
# Deception Services Config
# =======================
SERVICES = {
    "SSH": {"port": 22, "proto": "tcp", "banner": "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5"},
    "HTTP": {"port": 80, "proto": "tcp", "banner": "HTTP/1.1 200 OK\r\nServer: Apache/2.4.41\r\n\r\n"},
    "RDP": {"port": 3389, "proto": "tcp", "banner": None}, # Binary simulation
}

# =======================
# Custom Rules (Layer 3/4)
# =======================
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
NIC_TARGET = 'ens192'
NIC_PROBE  = 'ens224'

# VLAN Tagging
VLAN_MAP = {
    NIC_TARGET: None,
    NIC_PROBE: None,
}

# Gateway Mapping
GATEWAY_MAP = {
    NIC_TARGET: '192.168.23.1',
    NIC_PROBE: '192.168.10.1',
}

# =======================
# Port Deception Defaults
# =======================
# Ports that should respond with a template even if not strictly "closed"
DECEPTION_PORTS = [4441, 5551, 6661]

# =======================
# OS Fingerprint Templates (Advanced)
# =======================
FALLBACK_TTL = 64
FALLBACK_WINDOW = 8192

# Refined fingerprints: TTL, Window, DF bit, TCP Options
BASE_OS_TEMPLATES = {
    "linux": {
        "ttl": 64, "window": 5840, "df": True,
        # TSVal: Timestamp Value, TSecr: Timestamp Echo Reply
        "tcp_options": [('MSS', 1460), ('SAckOK', b''), ('NOP', b''), ('Timestamp', (0, 0)), ('WScale', 7)]
    },
    "win10": {
        "ttl": 128, "window": 8192, "df": True,
        "tcp_options": [('MSS', 1460), ('SAckOK', b''), ('NOP', b''), ('Timestamp', (0, 0)), ('WScale', 2)]
    },
}

OS_ALIASES = {
    "windows10": "win10", "ubuntu": "linux"
}

def get_os_fingerprint(os_name: str) -> dict:
    name = os_name.lower()
    resolved_name = OS_ALIASES.get(name, name)
    
    if resolved_name in BASE_OS_TEMPLATES:
        logging.info(f"🧹 Resolved OS '{os_name}' → '{resolved_name}'")
        template = BASE_OS_TEMPLATES[resolved_name].copy()
        
        # --- 新增：動態計算 Timestamp ---
        # 計算毫秒數 (Linux 通常為 1000Hz, Windows 為 10Hz/1000Hz, 這裡使用高精度)
        current_ts = int((time.time() - START_TIME) * 1000)
        
        # 替換 tcp_options 中的 Timestamp 佔位符
        new_options = []
        for opt in template["tcp_options"]:
            if opt[0] == 'Timestamp':
                # 類比 TSVal=current_ts, TSecr=0 (for SYN)
                new_options.append(('Timestamp', (current_ts, 0)))
            else:
                new_options.append(opt)
        
        template["tcp_options"] = new_options
        return template
    
    logging.warning(f"⚠ Unknown OS '{name}', using fallback values")
    return {"ttl": FALLBACK_TTL, "window": FALLBACK_WINDOW, "tcp_options": []}

def get_mac_address(nic: str) -> str:
    try:
        return get_if_hwaddr(nic)
    except Exception as e:
        logging.error(f"❌ Could not get MAC for {nic}: {e}")
        return "00:00:00:00:00:00"

def get_ip_address(nic: str) -> str:
    try:
        return get_if_addr(nic)
    except Exception:
        return "0.0.0.0"
