import logging
import random
from scapy.all import Ether, IP, TCP, UDP, ICMP
from ipaddress import ip_address, ip_network

EXCLUDE_SOURCES = [  # Example: filtered attackers or honeypots
    ip_network("192.168.10.0/24"),
]

def synthesize_response(pkt, template_bytes, ttl=None, window=None, deceiver=None):
    try:
        src_ip_str = pkt.l3_field.get("src_IP_str")
        if src_ip_str and any(ip_address(src_ip_str) in net for net in EXCLUDE_SOURCES):
            logging.debug(f"🚫 Dropping response to excluded source IP: {src_ip_str}")
            return None

        if random.random() < 0.05:  # 5% chance to simulate dropped response
            logging.debug("🎲 Randomized drop: simulating packet loss")
            return None

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
        ip.ttl = ttl if ttl is not None else random.randint(60, 128)
        ip.tos = deceiver.os_flags.get("tos", 0) if deceiver else ip.tos
        ip.id = deceiver.get_ip_id(src_ip_str) if deceiver else random.randint(0, 65535)

        if deceiver and deceiver.os_flags.get("df"):
            ip.flags = "DF"
        if deceiver and deceiver.os_flags.get("ecn"):
            ip.tos |= deceiver.os_flags["ecn"]

        # TCP response
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
            l4_layer = icmp

        else:
            logging.warning(f"❓ Unknown L4 protocol: {proto}")
            return None

        # Optional delay
        if deceiver and hasattr(deceiver, 'simulate_delay'):
            delay = deceiver.simulate_delay(pkt)
            if delay > 0:
                logging.debug(f"⏱️ Injecting delay: {delay:.3f}s")
                time.sleep(delay)

        return bytes(ether / ip / l4_layer)

    except Exception as e:
        logging.error(f"❌ synthesize_response failed: {e}")
        return None
