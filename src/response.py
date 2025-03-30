import logging
import random
from scapy.all import Ether, IP, TCP, UDP, ICMP

def synthesize_response(pkt, template_bytes, ttl=None, window=None, deceiver=None):
    try:
        # Unpack the original probe
        src_mac = pkt.l2_field.get("sMAC")
        dst_mac = pkt.l2_field.get("dMAC")
        src_ip = pkt.l3_field.get("src_IP")
        dst_ip = pkt.l3_field.get("dest_IP")
        proto = pkt.l4

        # Deconstruct template
        ether = Ether(template_bytes[:14])
        ip = IP(template_bytes[14:34])
        l4 = template_bytes[34:]

        # Overwrite dynamic fields
        ether.src = dst_mac
        ether.dst = src_mac

        ip.src = dst_ip
        ip.dst = src_ip
        ip.ttl = ttl if ttl is not None else ip.ttl
        ip.tos = deceiver.os_flags.get("tos", 0) if deceiver else ip.tos
        ip.id = deceiver.get_ip_id(src_ip) if deceiver else random.randint(0, 65535)

        if deceiver and deceiver.os_flags.get("df"):
            ip.flags = "DF"
        if deceiver and deceiver.os_flags.get("ecn"):
            ip.tos |= deceiver.os_flags["ecn"]

        # Handle protocol-specific patching
        if proto == "tcp":
            tcp = TCP(l4)
            tcp.sport = pkt.l4_field.get("dest_port")
            tcp.dport = pkt.l4_field.get("src_port")
            tcp.seq = random.randint(0, 4294967295)
            tcp.ack = pkt.l4_field.get("seq", 0) + 1
            tcp.flags = "SA"
            tcp.window = window if window else tcp.window

            if deceiver:
                tcp.options = deceiver.get_tcp_options(src_ip, ts_echo=pkt.l4_field.get("option_field", {}).get("ts_val", 0))

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

        final_packet = ether / ip / l4_layer
        return bytes(final_packet)

    except Exception as e:
        logging.error(f"❌ synthesize_response failed: {e}")
        return None
