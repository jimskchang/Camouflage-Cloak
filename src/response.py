import logging
import random
import time
from ipaddress import ip_address, ip_network

from scapy.all import Ether, IP, TCP, UDP, ICMP

# List of filtered source subnets to silently ignore
EXCLUDE_SOURCES = [
    ip_network("192.168.10.0/24"),  # Example: honeypot/Nmap segment
]

def synthesize_response(pkt, template_bytes, ttl=None, window=None, deceiver=None):
    try:
        src_ip_str = pkt.l3_field.get("src_IP_str")
        if src_ip_str and any(ip_address(src_ip_str) in net for net in EXCLUDE_SOURCES):
            logging.debug(f"🚫 Skipping response to excluded source IP: {src_ip_str}")
            return None

        if random.random() < 0.05:
            logging.debug("🎲 Simulating random drop (5%)")
            return None

        # Unpack L2/L3 from original probe
        src_mac = pkt.l2_field.get("sMAC")
        dst_mac = pkt.l2_field.get("dMAC")
        src_ip = pkt.l3_field.get("src_IP")
        dst_ip = pkt.l3_field.get("dest_IP")
        proto = pkt.l4

        # Rebuild Ethernet + IP from template
        ether = Ether(template_bytes[:14])
        ip = IP(template_bytes[14:34])
        l4 = template_bytes[34:]

        ether.src = dst_mac
        ether.dst = src_mac
        ip.src = dst_ip
        ip.dst = src_ip
        ip.ttl = ttl if ttl is not None else random.randint(60, 128)
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
            tcp.window = window if window else tcp.window
            if deceiver:
                tcp.options = deceiver.get_tcp_options(src_ip_str, ts_echo=pkt.l4_field.get("option_field", {}).get("ts_val", 0))
            l4_layer = tcp

        # UDP Response
        elif proto == "udp":
            udp = UDP(l4)
            udp.sport = pkt.l4_field.get("dest_port")
            udp.dport = pkt.l4_field.get("src_port")
            l4_layer = udp

        # ICMP Response (Echo Reply)
        elif proto == "icmp":
            icmp = ICMP(l4)
            if icmp.type == 8:  # Echo request
                icmp.type = 0   # Convert to echo reply
            l4_layer = icmp

        else:
            logging.warning(f"❓ Unsupported protocol in template: {proto}")
            return None

        # Optional delay injection (controlled by deceiver logic)
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
