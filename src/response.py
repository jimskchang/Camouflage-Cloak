import logging
import random
import time
import json
from ipaddress import ip_address, ip_network
from scapy.all import Ether, IP, TCP, UDP, ICMP, DNS, DNSRR
from datetime import datetime

from src.ja3_extractor import extract_ja3, match_ja3_rule
from src.fingerprint_utils import gen_key

# --- Configuration ---
EXCLUDE_SOURCES = [ip_network("192.168.10.0/24")]
JA3_OBSERVED_LOG = "ja3_observed.json"
JA3_OBSERVED = {}

# --- HTTP Banners ---
HTTP_BANNERS = {
    "default": b"HTTP/1.1 200 OK\r\nServer: Apache/2.4.41 (Unix)\r\nContent-Length: 13\r\n\r\nHello, World!",
    "ja3+chrome": b"HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\nContent-Length: 17\r\n\r\nHello from Chrome!",
    "ja3+curl": b"HTTP/1.1 200 OK\r\nServer: CamouflageHTTP/1.0\r\nContent-Length: 16\r\n\r\nHello curl user!"
}

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
            # 1. JA3 Tracking & Rules
            ja3 = extract_ja3(pkt.packet)
            if ja3:
                JA3_OBSERVED.setdefault(src_ip_str, []).append(ja3)
                rule = match_ja3_rule(ja3)
                if rule and rule["action"] == "drop":
                    return None

            # 2. Protocol Simulation
            payload = pkt.l4_field.get("raw_payload", b"")
            
            # HTTP/Web Simulation
            if dport in [80, 8080] and payload.startswith(b"GET"):
                return synthesize_http_response(pkt, payload)
            
            # RDP Simulation (Binary)
            elif dport == 3389 and payload.startswith(b"\x03\x00\x00"):
                return synthesize_rdp_response(pkt, RDP_CONN_CONFIRM)

        elif proto == "udp" and dport == 53:
            # Get spoof IP from deceiver if available, else default
            spoof_ip = deceiver.target_ip if deceiver else "1.2.3.4"
            return synthesize_dns_response(pkt, spoof_ip)

        # --- Default Deception (Template Based) ---
        return generate_template_response(pkt, template_bytes, ttl, window, deceiver)

    except Exception as e:
        logging.error(f"❌ synthesize_response failed: {e}")
        return None

def synthesize_http_response(pkt, payload):
    """Generates dynamic HTTP response based on user agent."""
    try:
        payload_text = payload.decode(errors="ignore")
        ua = ""
        for line in payload_text.split("\r\n"):
            if line.lower().startswith("user-agent:"):
                ua = line.split(":", 1)[-1].strip().lower()
                break
        
        if "curl" in ua:
            banner = HTTP_BANNERS["ja3+curl"]
        elif "chrome" in ua:
            banner = HTTP_BANNERS["ja3+chrome"]
        else:
            banner = HTTP_BANNERS["default"]
            
        return build_tcp_packet(pkt, banner, flags="PA")
    except Exception as e:
        logging.error(f"❌ HTTP Response failed: {e}")
        return None

def synthesize_rdp_response(pkt, payload):
    """Generates RDP X.224 Connection Confirm with correct TCP state."""
    logging.info(f"⚡ RDP Handshake from {pkt.l3_field.get('src_IP_str')}")
    # RDP uses standard PSH-ACK for handshake responses
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
    # Ensure TTL is set, default to 64 if not passed
    ip = IP(src=pkt.l3_field['dest_IP_str'], dst=pkt.l3_field['src_IP_str'], ttl=64)
    tcp = TCP(
        sport=sport or pkt.l4_field['dest_port'],
        dport=dport or pkt.l4_field['src_port'],
        flags=flags,
        # Proper sequence/ack numbers for session continuation
        seq=pkt.l4_field.get("ack_num", 0),
        ack=pkt.l4_field.get("seq", 0) + len(pkt.l4_field.get("raw_payload", b"")),
        window=window or pkt.l4_field.get("window", 8192)
    )
    return bytes(eth / ip / tcp / payload)

def build_udp_packet(pkt, payload, sport=None, dport=None):
    """Generic UDP packet builder."""
    eth = Ether(src=pkt.l2_field['dMAC'], dst=pkt.l2_field['sMAC'])
    ip = IP(src=pkt.l3_field['dest_IP_str'], dst=pkt.l3_field['src_IP_str'], ttl=64)
    udp = UDP(sport=sport or pkt.l4_field['dest_port'], dport=dport or pkt.l4_field['src_port'])
    return bytes(eth / ip / udp / payload)

def generate_template_response(pkt, template_bytes, ttl, window, deceiver):
    """Handles standard template-based packet forging."""
    try:
        # Re-construct base layers from template
        eth = Ether(template_bytes[:14])
        ip = IP(template_bytes[14:34])
        
        # Update IP layers with actual packet details
        ip.src = pkt.l3_field['dest_IP_str']
        ip.dst = pkt.l3_field['src_IP_str']
        ip.ttl = ttl or 64
        
        # Re-construct L4 layer
        l4_bytes = template_bytes[34:]
        if pkt.l4 == "tcp":
            l4_layer = TCP(l4_bytes)
            l4_layer.window = window or l4_layer.window
        elif pkt.l4 == "udp":
            l4_layer = UDP(l4_bytes)
        else:
            return None

        # Fix L4 ports and sequence numbers
        l4_layer.sport = pkt.l4_field['dest_port']
        l4_layer.dport = pkt.l4_field['src_port']
        
        return bytes(eth / ip / l4_layer)
    except Exception as e:
        logging.error(f"❌ Template generation failed: {e}")
        return None
