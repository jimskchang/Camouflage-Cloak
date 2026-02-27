import logging
import random
import re
from ipaddress import ip_address, ip_network
from scapy.all import Ether, IP, TCP, UDP, DNS, DNSRR
from datetime import datetime

# 導入新的設定和工具
from src.ja3_extractor import extract_ja3, match_ja3_rule
from src.settings import get_os_fingerprint, SERVICES

# --- Configuration ---
# 排除特定的源 IP 地址，例如信任的內部網路
EXCLUDE_SOURCES = [ip_network("192.168.10.0/24")]
JA3_OBSERVED = {}

# --- RDP Binary Payloads (X.224) ---
RDP_CONN_CONFIRM = b"\x03\x00\x00\x0b\x06\xd0\x00\x00\x12\x34\x00"

def synthesize_response(pkt, template_bytes, ttl=None, window=None, deceiver=None):
    """
    Main entry point for generating deception responses based on protocol and state.
    """
    try:
        src_ip_str = pkt.l3_field.get("src_IP_str")
        if src_ip_str and any(ip_address(src_ip_str) in net for net in EXCLUDE_SOURCES):
            return None

        # 5% Random drop for realism
        if random.random() < 0.05:
            return None

        proto = pkt.l4
        dport = pkt.l4_field.get("dest_port")

        # --- L7 Decoy Logic ---
        if proto == "tcp":
            # 1. JA3 Tracking (For TLS deception)
            ja3 = extract_ja3(pkt.packet)
            if ja3:
                JA3_OBSERVED.setdefault(src_ip_str, []).append(ja3)
                rule = match_ja3_rule(ja3)
                if rule and rule["action"] == "drop":
                    return None

            # 2. Protocol Simulation
            payload = pkt.l4_field.get("raw_payload", b"")
            
            # --- 使用 SERVICES 字典檢查 HTTP 服務 ---
            http_service = SERVICES.get("HTTP", {})
            if dport == http_service.get("port") and payload.startswith(b"GET"):
                return synthesize_http_response(pkt, payload)
            
            # RDP Simulation (Binary)
            elif dport == 3389 and payload.startswith(b"\x03\x00\x00"):
                return synthesize_rdp_response(pkt, RDP_CONN_CONFIRM)

        elif proto == "udp" and dport == 53:
            # DNS spoofing needs a target IP to advertise
            spoof_ip = deceiver.host if deceiver else "127.0.0.1"
            return synthesize_dns_response(pkt, spoof_ip)

        # --- Default Deception (Template Based with TCP Options) ---
        return generate_template_response(pkt, template_bytes, ttl, window, deceiver)

    except Exception as e:
        logging.error(f"❌ synthesize_response failed: {e}")
        return None

def synthesize_http_response(pkt, payload):
    """Generates dynamic, complex HTTP response based on user agent and SERVICES."""
    try:
        payload_text = payload.decode(errors="ignore")
        
        # 1. 解析 User-Agent
        ua_match = re.search(r'User-Agent:\s*(.*)', payload_text, re.IGNORECASE)
        ua = ua_match.group(1).lower() if ua_match else "unknown"
        
        # 2. 獲取服務基礎配置
        http_service = SERVICES.get("HTTP", {})
        
        # 3. 根據 UA 選擇不同的 Banner 模板和內容
        if "curl" in ua:
            server_header = "Server: CamouflageHTTP/1.0"
            content = b"<html><body><h1>Curl User Detected</h1></body></html>"
        elif "mozilla" in ua or "chrome" in ua:
            server_header = "Server: Apache/2.4.41 (Ubuntu)"
            content = b"<html><body><h1>Welcome to our secure decoy site</h1></body></html>"
        else:
            server_header = "Server: GenericWeb/1.0"
            content = b"<html><body><h1>Deception Site</h1></body></html>"

        # 4. 動態構建 Headers
        date_str = datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')
        
        # 構建 HTTP Response 字節流
        response_header = (
            f"HTTP/1.1 200 OK\r\n"
            f"Date: {date_str}\r\n"
            f"{server_header}\r\n"
            f"Content-Type: text/html\r\n"
            f"Content-Length: {len(content)}\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        ).encode('utf-8')
        
        full_response = response_header + content
            
        return build_tcp_packet(pkt, full_response, flags="PA")
    
    except Exception as e:
        logging.error(f"❌ Complex HTTP Response failed: {e}")
        return None

def synthesize_rdp_response(pkt, payload):
    """Generates RDP X.224 Connection Confirm."""
    logging.info(f"⚡ RDP Handshake from {pkt.l3_field.get('src_IP_str')}")
    return build_tcp_packet(pkt, payload, flags="PA")

def synthesize_dns_response(pkt, spoof_ip):
    """Generates DNS spoof response using Scapy."""
    try:
        dns_req = pkt.l4_field.get("raw_payload", b"")
        dns_header = DNS(dns_req)
        
        if not dns_header.qd:
            return None

        # Build Response
        dns_resp = DNS(
            id=dns_header.id,
            qr=1,
            aa=1,
            qd=dns_header.qd,
            an=DNSRR(rrname=dns_header.qd.qname, ttl=60, rdata=spoof_ip)
        )
        
        return build_udp_packet(pkt, bytes(dns_resp), sport=53)
    except Exception as e:
        logging.warning(f"⚠️ DNS spoof error: {e}")
        return None

# --- Helper Functions for Packet Building ---

def build_tcp_packet(pkt, payload, flags="SA", sport=None, dport=None, window=None):
    """Generic TCP packet builder."""
    eth = Ether(src=pkt.l2_field['dMAC'], dst=pkt.l2_field['sMAC'])
    ip = IP(src=pkt.l3_field['dest_IP_str'], dst=pkt.l3_field['src_IP_str'], ttl=64)
    
    tcp = TCP(
        sport=sport or pkt.l4_field['dest_port'],
        dport=dport or pkt.l4_field['src_port'],
        flags=flags,
        seq=pkt.l4_field.get("ack_num", 0),
        ack=pkt.l4_field.get("seq", 0) + len(pkt.l4_field.get("raw_payload", b"")),
        window=window or 8192
    )
    return bytes(eth / ip / tcp / payload)

def build_udp_packet(pkt, payload, sport=None, dport=None):
    """Generic UDP packet builder."""
    eth = Ether(src=pkt.l2_field['dMAC'], dst=pkt.l2_field['sMAC'])
    ip = IP(src=pkt.l3_field['dest_IP_str'], dst=pkt.l3_field['src_IP_str'], ttl=64)
    udp = UDP(sport=sport or pkt.l4_field['dest_port'], dport=dport or pkt.l4_field['src_port'])
    return bytes(eth / ip / udp / payload)

def generate_template_response(pkt, template_bytes, ttl, window, deceiver):
    """Handles template-based packet forging, patching IPs, TTLs, and TCP Options."""
    try:
        # 1. Parse existing template to Scapy layers
        eth = Ether(template_bytes[:14])
        ip = IP(template_bytes[14:34])
        
        # 2. Patch IP layers
        ip.src = pkt.l3_field['dest_IP_str']
        ip.dst = pkt.l3_field['src_IP_str']
        ip.ttl = ttl or 64
        
        # 3. Patch Ethernet Layers
        eth.src = pkt.l2_field['dMAC']
        eth.dst = pkt.l2_field['sMAC']
        
        # 4. Handle L4 patching
        l4_bytes = template_bytes[34:]
        if pkt.l4 == "tcp":
            l4_layer = TCP(l4_bytes)
            
            # --- 動態處理 TCP Options (包含 Timestamp) ---
            if deceiver and hasattr(deceiver, 'os'):
                # 這裡會呼叫 settings.py 中的函數，獲取帶有動態 Timestamp 的配置
                os_config = get_os_fingerprint(deceiver.os)
                if "tcp_options" in os_config:
                    l4_layer.options = os_config["tcp_options"]
                if "window" in os_config:
                    l4_layer.window = os_config["window"]
            
            # 覆蓋傳入的參數（如果有單獨傳入 window）
            if window:
                l4_layer.window = window
                
            l4_layer.sport = pkt.l4_field['dest_port']
            l4_layer.dport = pkt.l4_field['src_port']
            
            # 重新計算校驗和以確保封包有效
            del ip.chksum
            del l4_layer.chksum

        elif pkt.l4 == "udp":
            l4_layer = UDP(l4_bytes)
            l4_layer.sport = pkt.l4_field['dest_port']
            l4_layer.dport = pkt.l4_field['src_port']
        else:
            return None
        
        return bytes(eth / ip / l4_layer)
    except Exception as e:
        logging.error(f"❌ Template generation failed: {e}")
        return None
