import os
import logging
import time
import random
import copy
from scapy.all import get_if_addr, get_if_hwaddr

# =======================
# Project Paths & Storage
# =======================
# 建立根目錄與指紋資料庫儲存路徑 [4]
PROJECT_PATH = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OS_RECORD_PATH = os.path.join(PROJECT_PATH, "os_record")
os.makedirs(OS_RECORD_PATH, exist_ok=True)

# 持久化引擎緩存檔案路徑 [5]
LEARNED_FINGERPRINTS_FILE = os.path.join(OS_RECORD_PATH, "learned_fingerprints.json")

# 安全地回推時鐘，提供精確的多日系統上線時間指紋 (Uptime Signatures) [5]
START_TIME = time.time() - random.randint(86400, 2592000)

# =======================
# Toggle Settings
# =======================
# 允許系統在掃描期間自動註冊新的指紋配置 [5]
AUTO_LEARN_MISSING = True

# =======================
# Protocol Header Lengths
# =======================
# 標準 RFC 協定長度定義，用於封包解析與建構 [6]
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
# 定義用於誤導服務版本偵測的橫幅 (Banners) [6, 7]
SERVICES = {
    "SSH": {"port": 22, "proto": "tcp", "banner": "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5"},
    "HTTP": {"port": 80, "proto": "tcp", "banner": "HTTP/1.1 200 OK\r\nServer: Apache/2.4.41\r\n\r\n"},
    "RDP": {"port": 3389, "proto": "tcp", "banner": None}, 
}

# =======================
# Custom Rules (Layer 3/4)
# =======================
# 規定工具如何回應特定埠號探測的規則矩陣 [7]
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
# 將特定 TLS 指紋匹配至欺騙模板的規則 [8]
JA3_RULES = [
    {
        "ja3": "771,4865-4866-49195-49196,0-11-10,29-23-24,0",
        "action": "template",
        "template_name": "ja3_tls_windows11",
        "log": "🎭 Routing Nmap TLS probe to JA3-Windows11 template"
    }
]

# =======================
# Network Interfaces & Environment IPs
# =======================
# 根據來源 [2, 3] 與架構圖 [1] 配置的雙網卡環境：
NIC_TARGET = 'ens192' # 連接至真實目標伺服器 (對應圖中 NIC2)
NIC_PROBE  = 'ens224' # 連接至攻擊者/掃描器 (對應圖中 NIC1)

# 來源文件 [2] 指定的 Camouflage Cloak 主機 IP
HOST = "192.168.23.206" 

# VLAN 標記配置 [3]
VLAN_MAP = {
    NIC_TARGET: None,
    NIC_PROBE: None,
}

# 閘道器對應表，用於正確路由欺騙回應 [3]
GATEWAY_MAP = {
    NIC_TARGET: '192.168.23.1',
    NIC_PROBE: '192.168.10.1',
}

# =======================
# Port Deception Defaults
# =======================
# 正確配置常用的欺騙埠號列表，使關閉的埠號在 Nmap 掃描中顯得開放 [9, 10]
DECEPTION_PORTS = [11-18]

# =======================
# OS Fingerprint Templates (Advanced)
# =======================
# 各類作業系統的基準網路指紋特徵 [19, 20]
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
# 根據觀察到的指標對未知指紋進行分類的邏輯 [21]
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
    """動態檢索作業系統指紋，並套用啟發式規則 [21, 22]"""
    name = os_name.lower()
    is_learned_unknown = name.startswith("unknown_learned")
    resolved_name = "heuristic_match" if is_learned_unknown else OS_ALIASES.get(name, name)

    if resolved_name == "heuristic_match" and packet_features:
        for rule in HEURISTIC_RULES:
            if rule["match"](packet_features.get('window', 0),
                           packet_features.get('ttl', 0),
                           packet_features.get('options', [])):
                resolved_name = rule["name"]
                break

    if resolved_name == "heuristic_match":
        resolved_name = "linux"

    if resolved_name in BASE_OS_TEMPLATES:
        template = copy.deepcopy(BASE_OS_TEMPLATES[resolved_name])
        # 計算精確的 TCP 時間戳記 (ms) [23, 24]
        current_ts = int((time.time() - START_TIME) * 1000)
        new_options = []
        for opt in template["tcp_options"]:
            if opt == 'Timestamp':
                new_options.append(('Timestamp', (current_ts, 0)))
            else:
                new_options.append(opt)
        template["tcp_options"] = new_options
        return template

    return {"ttl": FALLBACK_TTL, "window": FALLBACK_WINDOW, "tcp_options": []}

def get_mac_address(nic: str) -> str:
    """安全地檢索指定網卡的硬體 MAC 位址 [24, 25]"""
    try:
        return get_if_hwaddr(nic)
    except Exception:
        return "00:00:00:00:00:00"
       
