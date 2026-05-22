import logging
import random
import re
from ipaddress import ip_address, ip_network
from scapy.all import Ether, IP, TCP, UDP, DNS, DNSRR
from datetime import datetime

# Import components
from src.ja3_extractor import extract_ja3, match_ja3_rule
from src.fingerprint_gen import generateKey
from src.settings import get_os_fingerprint, SERVICES
from src.learning_engine import FingerprintLearner

# --- Configuration ---
EXCLUDE_SOURCES = [ip_network("192.168.10.0/24")]
JA3_OBSERVED = {}

# Initialize learning engine
learner = FingerprintLearner()

# RDP Binary Payloads (X.224)
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
            
            # Check HTTP configuration space
            http_service = SERVICES.get("HTTP", {})
            if dport == http_service.get("port") and payload.startswith(b"GET"):
                return synthesize_http_response(pkt, payload)
            
            # RDP Simulation (Binary)
            elif dport == 3389 and payload.startswith(b"\x03\x00\x00"):
                return synthesize_rdp_response(pkt, RDP_CONN_CONFIRM)

            # --- Automatic Fingerprint Learning Matching Engine ---
            current_hash = generateKey(pkt, "TCP")
            os_name = learner.match_or_learn(current_hash, pkt)
            
            if os_name:
                packet_features = {
                    'window': pkt.l4_field.get('window'),
                    'ttl': pkt.l3_field.get('ttl'),
                    'options': pkt.l4_field.get('option_field')
                }
                os_config = get_os_fingerprint(os_name, packet_features)
                
                # Dynamic override variables mapping assignments
                ttl = os_config.get("ttl")
                window = os_config.get("window")

        elif proto == "udp" and dport == 53:
            spoof_ip = deceiver.host if deceiver else "127.0.0.1"
            return synthesize_dns_response(pkt, spoof_ip)

        # Default Fallback Deception (Template Based with Dynamic TCP Options)
        return generate_template_response(pkt, template_bytes, ttl, window, deceiver)

    except Exception as e:
        logging.error(f"❌ synthesize_response failed: {e}")
        return None

def synthesize_http_response(pkt, payload):
    """Generates dynamic, complex HTTP response based on user agent and SERVICES."""
    try:
        payload_text = payload.decode(errors="ignore")
        
        # Parse User-Agent
        ua_match = re.search(r'User-Agent:\s*(.*)', payload_text, re.IGNORECASE)
        ua = ua_match.group(1).lower() if ua_match else "unknown"
        
        # Select appropriate banner template matching UA profile signatures
        if "curl" in ua:
            server_header = "Server: CamouflageHTTP/1.0"
            content = b"<html><body><h1>Curl User Detected</h1></body></html>"
        elif "mozilla" in ua or "chrome" in ua:
            server_header = "Server: Apache/2.4.41 (Ubuntu)"
            content = b"<html><body><h1>Welcome to our secure decoy site</h1></body></html>"
        else:
            server_header = "Server: GenericWeb/1.0"
            content = b"<html><body><h1>Deception Site</h1></body></html>"

        date_str = datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')
        
        response_header = (
            f"HTTP/1.1 200 OK\r\n"
            f"Date: {date_str}\r\n"
            f"{server_header}\r\n"
            f"Content-Type: text/html\r\n"
            f"Content-Length: {len(content)}\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        ).encode('utf-8')
        
        return build_tcp_packet(pkt, response_header + content, flags="PA")
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
    eth = Ether(src=pkt.l2_field.get('dMAC'), dst=pkt.l2_field.get('sMAC'))
    ip = IP(src=pkt.l3_field.get('dest_IP_str'), dst=pkt.l3_field.get('src_IP_str'), ttl=64)
    
    # FIXED: Sane sequence calculations handling TCP controls vs payload boundaries
    incoming_flags = pkt.l4_field.get("flags", 0)
    payload_len = len(pkt.l4_field.get("raw_payload", b""))
    
    # Consume state validation length sequence numbers correctly on SYN/FIN commands
    step_offset = 1 if (incoming_flags & 0x02 or incoming_flags & 0x01) else 0
    calculated_ack = pkt.l4_field.get("seq", 0) + payload_len + step_offset

    tcp = TCP(
        sport=sport or pkt.l4_field.get('dest_port'),
        dport=dport or pkt.l4_field.get('src_port'),
        flags=flags,
        seq=pkt.l4_field.get("ack_num", 0),
        ack=calculated_ack,
        window=window or 8192
    )
    return bytes(eth / ip / tcp / payload)

def build_udp_packet(pkt, payload, sport=None, dport=None):
    """Generic UDP packet builder."""
    eth = Ether(src=pkt.l2_field.get('dMAC'), dst=pkt.l2_field.get('sMAC'))
    ip = IP(src=pkt.l3_field.get('dest_IP_str'), dst=pkt.l3_field.get('src_IP_str'), ttl=64)
    udp = UDP(sport=sport or pkt.l4_field.get('dest_port'), dport=dport or pkt.l4_field.get('src_port'))
    return bytes(eth / ip / udp / payload)

def generate_template_response(pkt, template_bytes, ttl, window, deceiver):
    """Handles template-based packet forging, patching IPs, TTLs, and TCP Options safely."""
    try:
        # FIXED: Use Scapy's native type unpacking factory methods instead of hardcoded byte slicing lengths
        base_packet = Ether(template_bytes)
        
        if not base_packet.haslayer(IP):
            return None
            
        eth_layer = base_packet
        ip_layer = base_packet[IP]
        
        # Patch Base Network Layer parameters safely
        ip_layer.src = pkt.l3_field.get('dest_IP_str')
        ip_layer.dst = pkt.l3_field.get('src_IP_str')
        ip_layer.ttl = ttl or 64
        
        eth_layer.src = pkt.l2_field.get('dMAC')
        eth_layer.dst = pkt.l2_field.get('sMAC')
        
        # Handle Transport configurations
        if pkt.l4 == "tcp" and base_packet.haslayer(TCP):
            l4_layer = base_packet[TCP]
            
            # Dynamic TCP Options profile formatting modifications
            if deceiver and hasattr(deceiver, 'os'):
                os_config = get_os_fingerprint(deceiver.os)
                if "tcp_options" in os_config:
                    l4_layer.options = os_config["tcp_options"]
                if "window" in os_config:
                    l4_layer.window = os_config["window"]
            
            if window:
                l4_layer.window = window
                
            l4_layer.sport = pkt.l4_field.get('dest_port')
            l4_layer.dport = pkt.l4_field.get('src_port')
            
            # Clear historical tracking blocks to force calculation mechanics across Scapy engines
            del ip_layer.chksum
            del l4_layer.chksum

        elif pkt.l4 == "udp" and base_packet.haslayer(UDP):
            l4_layer = base_packet[UDP]
            l4_layer.sport = pkt.l4_field.get('dest_port')
            l4_layer.dport = pkt.l4_field.get('src_port')
            del ip_layer.chksum
            del l4_layer.chksum
        else:
            return None
        
        return bytes(eth_layer)
    except Exception as e:
        logging.error(f"❌ Template generation failed: {e}")
        return None
