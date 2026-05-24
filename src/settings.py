import os
import logging
import time
import random
import copy
from scapy.all import get_if_addr, get_if_hwaddr

# =======================
# 1. 專案路徑與存儲設定
# =======================
# 定義根目錄與指紋資料庫儲存路徑 [1]
PROJECT_PATH = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OS_RECORD_PATH = os.path.join(PROJECT_PATH, "os_record")
os.makedirs(OS_RECORD_PATH, exist_ok=True)

# 學習指紋的 JSON 緩存檔案路徑 [4]
LEARNED_FINGERPRINTS_FILE = os.path.join(OS_RECORD_PATH, "learned_fingerprints.json")

# 安全地回推系統啟動時間，以模擬長達數天的運作特徵 (Uptime Signatures) [4]
START_TIME = time.time() - random.randint(86400, 2592000)

# =======================
# 2. 網路介面自定義 (NIC Configuration)
# =======================
# 根據架構圖與您的需求配置實體網卡 [2]
# NIC_PROBE: 連接攻擊者/掃描器 (例如 Nmap)
NIC_PROBE  = 'eth0'  

# NIC_TARGET: 連接您要保護的真實目標伺服器
NIC_TARGET = 'ens33' 

# 偽裝主機（Camouflage Cloak）本身的 IP 位址 [5]
# 請根據您的網路環境修改此值
HOST = "192.168.1.100" 

# 閘道器對應表，確保欺騙回應封包能正確路由 [2]
GATEWAY_MAP = {
    NIC_TARGET: '192.168.1.1',
    NIC_PROBE:  '192.168.1.1',
}

# VLAN 標記配置 (若您的網路環境未使用 VLAN，請保持為 None) [2]
VLAN_MAP = {
    NIC_TARGET: None,
    NIC_PROBE: None,
}

# =======================
# 3. 欺騙服務與自定義規則
# =======================
# 模擬開放埠號的服務橫幅 (Banners) [6]
SERVICES = {
    "SSH": {"port": 22, "proto": "tcp", "banner": "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5"},
    "HTTP": {"port": 80, "proto": "tcp", "banner": "HTTP/1.1 200 OK\r\nServer: Apache/2.4.41\r\n\r\n"},
    "RDP": {"port": 3389, "proto": "tcp", "banner": None}, 
}

# 自定義通訊協定規則 (L3/L4) [7]
CUSTOM_RULES = [
    {
        "proto": "tcp", "port": 80, "flags": "S", "action": "drop",
        "log": "🔒 隱身模式：丟棄對 80 埠的 TCP SYN 請求"
    },
    {
        "proto": "udp", "port": 53, "action": "icmp_unreachable",
        "log": "📋 偽裝回應：對 UDP 53 傳送 ICMP Unreachable"
    }
]

# TLS/JA3 指紋匹配規則 [8]
JA3_RULES = [
    {
        "ja3": "771,4865-4866-49195-49196,0-11-10,29-23-24,0",
        "action": "template",
        "template_name": "ja3_tls_windows11",
        "log": "🎭 路由 Nmap TLS 探測至 Windows 11 模板"
    }
]

# =======================
# 4. 作業系統指紋預設模板 [9, 10]
# =======================
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
    }
}

OS_ALIASES = {
    "windows10": "win10",
    "ubuntu": "linux"
}

# 自動學習模式切換 [4]
AUTO_LEARN_MISSING = True

# 啟發式學習規則 [3]
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

# =======================
# 5. 核心工具函數
# =======================
def get_os_fingerprint(os_name: str, packet_features: dict = None) -> dict:
    """動態檢索 OS 指紋，並套用啟發式規則處理未知配置 [3, 11]"""
    name = os_name.lower()
    resolved_name = OS_ALIASES.get(name, name)

    if resolved_name in BASE_OS_TEMPLATES:
        template = copy.deepcopy(BASE_OS_TEMPLATES[resolved_name])
        # 計算精確的 TCP 時間戳 (ms)
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
    """安全地獲取指定網卡的硬體 MAC 位址 [12]"""
    try:
        return get_if_hwaddr(nic)
    except Exception as e:
        logging.error(f"❌ 無法獲取網卡 {nic} 的 MAC 位址: {e}")
        return "00:00:00:00:00:00"

# 通訊協定長度常數 [6]
ETH_HEADER_LEN = 14
IP_HEADER_LEN = 20
ARP_HEADER_LEN = 28
TCP_HEADER_LEN = 20
UDP_HEADER_LEN = 8
ICMP_HEADER_LEN = 8
L3_PROC = ['ip', 'arp']
L4_PROC = ['tcp', 'udp', 'icmp']
       
