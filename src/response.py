import logging
import random
import time
import json
from ipaddress import ip_address, ip_network
from scapy.all import Ether, IP, TCP, UDP, ICMP
from dpkt.ssl import TLSRecord, TLSHandshake, TLSClientHello
import hashlib
import os

# List of filtered source subnets to silently ignore
EXCLUDE_SOURCES = [
    ip_network("192.168.10.0/24"),
]

JA3_LOG_PATH = "os_record/ja3_fingerprints.json"
ja3_store = {}


def extract_l7_signature(pkt):
    payload = pkt.l4_field.get("payload", b"")
    if not payload:
        return None, None

    # DNS detection
    if pkt.l4_field.get("dest_port") == 53 and len(payload) > 12:
        return "DNS", None

    # HTTP GET/POST detection
    if payload.startswith(b"GET") or payload.startswith(b"POST"):
        return "HTTP", None

    # TLS JA3 hash
    try:
        record = TLSRecord(payload)
        if isinstance(record.data, TLSHandshake):
            hs = record.data
            if isinstance(hs.data, TLSClientHello):
                ja3 = build_ja3(hs.data)
                return "TLS", ja3
    except Exception:
        pass

    return None, None


def build_ja3(ch: TLSClientHello) -> str:
    try:
        ja3_fields = [
            str(ch.version),
            "-".join(str(c) for c in ch.ciphers),
            "-".join(str(e) for e in (ch.extensions or [])),
            "-".join(str(c) for c in getattr(ch, "elliptic_curves", [])),
            "-".join(str(p) for p in getattr(ch, "ec_point_formats", []))
        ]
        ja3_str = ",".join(ja3_fields)
        return hashlib.md5(ja3_str.encode()).hexdigest()
    except Exception as e:
        logging.warning(f"⚠️ Failed JA3 parse: {e}")
        return "unknown"


def log_ja3(src_ip, ja3_hash):
    if not src_ip or not ja3_hash:
        return
    ja3_store.setdefault(src_ip, set()).add(ja3_hash)
    try:
        with open(JA3_LOG_PATH, "w") as f:
            serializable = {k: list(v) for k, v in ja3_store.items()}
            json.dump(serializable, f, indent=2)
        logging.debug(f"📝 Logged JA3 hash {ja3_hash} for {src_ip}")
    except Exception as e:
        logging.warning(f"⚠️ Failed to save JA3 log: {e}")


def synthesize_response(pkt, template_bytes, ttl=None, window=None, deceiver=None):
    try:
        src_ip_str = pkt.l3_field.get("src_IP_str")
        if src_ip_str and any(ip_address(src_ip_str) in net for net in EXCLUDE_SOURCES):
            logging.debug(f"🚫 Skipping response to excluded source IP: {src_ip_str}")
            return None

        if random.random() < 0.05:
            logging.debug("🎲 Simulating random drop (5%)")
            return None

        # Unpack packet
        src_mac = pkt.l2_field.get("sMAC")
        dst_mac = pkt.l2_field.get("dMAC")
        src_ip = pkt.l3_field.get("src_IP")
        dst_ip = pkt.l3_field.get("dest_IP")
        proto = pkt.l4

        ether = Ether(template_bytes[:14])
        ip = IP(template_bytes[14:34])
        l4 = template_bytes[34:]

        ether.src = dst_mac
        ether.dst = src_mac
        ip.src = dst_ip
        ip.dst = src_ip
        ip.ttl = ttl if ttl else random.randint(60, 128)
        ip.id = deceiver.get_ip_id(src_ip_str) if deceiver else random.randint(0, 65535)
        ip.tos = deceiver.os_flags.get("tos", 0) if deceiver else ip.tos
        if deceiver and deceiver.os_flags.get("df"):
            ip.flags = "DF"
        if deceiver and deceiver.os_flags.get("ecn"):
            ip.tos |= deceiver.os_flags["ecn"]

        # Deep L7 detection (JA3, HTTP, DNS)
        l7_proto, ja3_hash = extract_l7_signature(pkt)
        if ja3_hash:
            log_ja3(src_ip_str, ja3_hash)
            if ja3_hash in getattr(deceiver, "JA3_TEMPLATE_MAP", {}):
                alt_template = deceiver.JA3_TEMPLATE_MAP[ja3_hash]
                if alt_template:
                    logging.debug(f"🔁 Switching to JA3-specific response template for {ja3_hash}")
                    return alt_template

        # L4 response
        if proto == "tcp":
            tcp = TCP(l4)
            tcp.sport = pkt.l4_field.get("dest_port")
            tcp.dport = pkt.l4_field.get("src_port")
            tcp.seq = random.randint(0, 4294967295)
            tcp.ack = pkt.l4_field.get("seq", 0) + 1
            tcp.flags = "SA"
            tcp.window = window or tcp.window
            if deceiver:
                tcp.options = deceiver.get_tcp_options(src_ip_str, ts_echo=pkt.l4_field.get("option_field", {}).get("ts_val", 0))
            l4_layer = tcp

        elif proto == "udp":
            udp = UDP(l4)
            udp.sport = pkt.l4_field.get("dest_port")
            udp.dport = pkt.l4_field.get("src_port")
            l4_layer = udp

        elif proto == "icmp":
            icmp = ICMP(l4)
            if icmp.type == 8:
                icmp.type = 0
            l4_layer = icmp

        else:
            logging.warning(f"❓ Unsupported protocol in template: {proto}")
            return None

        if deceiver and hasattr(deceiver, 'simulate_delay'):
            try:
                delay = deceiver.simulate_delay(pkt)
                if delay > 0:
                    logging.debug(f"⏱️ Injecting artificial delay: {delay:.3f}s")
                    time.sleep(delay)
            except Exception as e:
                logging.warning(f"⚠️ simulate_delay error: {e}")

        return bytes(ether / ip / l4_layer)

    except Exception as e:
        logging.error(f"❌ synthesize_response failed: {e}")
        return None
