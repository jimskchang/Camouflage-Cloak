import logging
import random
import time
import json
from ipaddress import ip_address, ip_network
from scapy.all import Ether, IP, TCP, UDP, ICMP, DNS, DNSRR, DNSQR
from datetime import datetime

# 導入新的設定和工具
from src.ja3_extractor import extract_ja3, match_ja3_rule
# --- 修改處 1: 導入 SERVICES，移除 HTTP_BANNERS ---
from src.settings import get_os_fingerprint, SERVICES

# --- Configuration ---
# 排除特定的源 IP 地址，例如信任的內部網路
EXCLUDE_SOURCES = [ip_network("192.168.10.0/24")]
JA3_OBSERVED_LOG = "ja3_observed.json"
JA3_OBSERVED = {}

# --- RDP Binary Payloads (X.224) ---
# Connection Confirm PDU
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
            # 1. JA3 Tracking
            ja3 = extract_ja3(pkt.packet)
            if ja3:
                JA3_OBSERVED.setdefault(src_ip_str, []).append(ja3)
                rule = match_ja3_rule(ja3)
                if rule and rule["action"] == "drop":
                    return None

            # 2. Protocol Simulation
            payload = pkt.l4_field.get("raw_payload", b"")
            
            # --- 修改處 2: 檢查 SERVICES 字典中定義的 HTTP 埠 ---
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

        # --- Default Deception (Template Based) ---
        return generate_template_response(pkt, template_bytes, ttl, window, deceiver)

    except Exception as e:
        logging.error(f"❌ synthesize_response failed: {e}")
        return None

def synthesize_http_response(pkt, payload):
    """Generates dynamic HTTP response based on user agent and SERVICES dict."""
    try:
        payload_text = payload.decode(errors="ignore")
        ua = ""
        for line in payload_text.split("\r\n"):
            if line.lower().startswith("user-agent:"):
                ua = line.split(":", 1)[-1].strip().lower()
                break
        
        # --- 修改處 3: 從 SERVICES 字典獲取 Banner ---
        http_service = SERVICES.get("HTTP", {})
        banner = http_service.get("banner", b"HTTP/1.1 200 OK\r\n\r\n")

        # 這裡可以根據 UA 修改 banner，但最好是在 settings.py 定義更複雜的邏輯
        # if "curl" in ua: ...
            
        return build_tcp_packet(pkt, banner.encode() if isinstance(banner, str) else banner, flags="PA")
    except Exception as e:
        logging.error(f"❌ HTTP Response failed: {e}")
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
    # Note: L2 MAC addresses should be swapped from request to response
    eth = Ether(src=pkt.l2_field['dMAC'], dst=pkt.l2_field['sMAC'])
    
    # Use standard TTL or specific one passed in
    ip = IP(src=pkt.l3_field['dest_IP_str'], dst=pkt.l3_field['src_IP_str'], ttl=64)
    
    tcp = TCP(
        sport=sport or pkt.l4_field['dest_port'],
        dport=dport or pkt.l4_field['src_port'],
        flags=flags,
        # Correctly handle sequence numbers for response
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
    """Handles standard template-based packet forging, patching IPs and TTLs."""
    try:
        # 1. Parse existing template to Scapy layers
        eth = Ether(template_bytes[:14])
        ip = IP(template_bytes[14:34])
        
        # 2. Patch IP layers with current context
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
            l4_layer.window = window or l4_layer.window
            l4_layer.sport = pkt.l4_field['dest_port']
            l4_layer.dport = pkt.l4_field['src_port']
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
