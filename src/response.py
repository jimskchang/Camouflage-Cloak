# src/response.py
import logging
import random
import time
from ipaddress import ip_address, ip_network
from scapy.all import Ether, IP, TCP, UDP, ICMP, Raw

from src.ja3_extractor import extract_ja3
from src.settings import EXCLUDE_SOURCES, JA3_RULES

JA3_LOG = {}

def synthesize_response(pkt, template_bytes, ttl=None, window=None, deceiver=None):
    try:
        src_ip_str = pkt.l3_field.get("src_IP_str")
        if src_ip_str and any(ip_address(src_ip_str) in net for net in EXCLUDE_SOURCES):
            logging.debug(f"🚫 Skipping response to excluded source IP: {src_ip_str}")
            return None

        # Extract JA3 if present
        ja3_hash = None
        if pkt.l4 == "tcp" and pkt.l4_field.get("dest_port") in (443, 8443, 4443):
            payload = pkt.l4_field.get("payload", b"")
            ja3_hash = extract_ja3(payload)
            if ja3_hash:
                JA3_LOG.setdefault(src_ip_str, set()).add(ja3_hash)
                logging.info(f"🔐 JA3={ja3_hash} from {src_ip_str}")

                # Apply JA3_RULES
                for rule in JA3_RULES:
                    if rule.get("ja3") == ja3_hash:
                        action = rule.get("action", "drop")
                        if action == "drop":
                            logging.info(f"🚫 Dropping based on JA3 rule {ja3_hash}")
                            return None
                        elif action == "template" and "template" in rule:
                            template_bytes = rule["template"]
                            break

        if random.random() < 0.05:
            logging.debug("🎲 Simulating random drop (5%)")
            return None

        # Unpack base
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
        ip.ttl = ttl or random.randint(60, 128)
        ip.id = deceiver.get_ip_id(src_ip_str) if deceiver else random.randint(0, 65535)
        ip.tos = deceiver.os_flags.get("tos", 0) if deceiver else ip.tos
        if deceiver and deceiver.os_flags.get("df"):
            ip.flags = "DF"
        if deceiver and deceiver.os_flags.get("ecn"):
            ip.tos |= deceiver.os_flags["ecn"]

        # TCP Response
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
