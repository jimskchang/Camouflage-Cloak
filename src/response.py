from scapy.all import Ether, IP, TCP, UDP, ICMP, ARP
import logging
import random

def synthesize_response(pkt, template: bytes, ttl: int = 64, window: int = 8192, deceiver=None) -> bytes:
    try:
        scapy_pkt = Ether(template)

        # Handle IP header
        if IP in scapy_pkt:
            scapy_pkt[IP].dst = pkt.l3_field.get("src_IP_str", pkt.src_ip)
            scapy_pkt[IP].src = pkt.l3_field.get("dest_IP_str", pkt.dst_ip)
            scapy_pkt[IP].ttl = ttl
            if deceiver:
                scapy_pkt[IP].id = deceiver.get_ip_id()
            else:
                scapy_pkt[IP].id = random.randint(0, 65535)
            del scapy_pkt[IP].chksum

        # TCP Response
        if TCP in scapy_pkt:
            scapy_pkt[TCP].sport = pkt.l4_field.get("dest_port", 1234)
            scapy_pkt[TCP].dport = pkt.l4_field.get("src_port", 1234)
            scapy_pkt[TCP].window = window
            scapy_pkt[TCP].flags = "SA"  # default to SYN-ACK
            del scapy_pkt[TCP].chksum

            # ⬇️ Inject TCP Options
            if deceiver:
                src_ip = pkt.l3_field.get("src_IP")
                if src_ip:
                    src_ip_str = pkt.l3_field.get("src_IP_str", pkt.src_ip)
                    ts_echo = pkt.tcp_options.get("TSval", 0) if hasattr(pkt, 'tcp_options') else 0
                    scapy_pkt[TCP].options = deceiver.get_tcp_options(src_ip_str, ts_echo)

        # UDP Response
        if UDP in scapy_pkt:
            scapy_pkt[UDP].sport = pkt.l4_field.get("dest_port", 1234)
            scapy_pkt[UDP].dport = pkt.l4_field.get("src_port", 1234)
            del scapy_pkt[UDP].chksum

        # ICMP Response
        if ICMP in scapy_pkt:
            scapy_pkt[ICMP].type = 0  # Echo Reply
            del scapy_pkt[ICMP].chksum

        # ARP Response
        if ARP in scapy_pkt:
            scapy_pkt[ARP].op = 2  # ARP reply
            scapy_pkt[ARP].psrc = pkt.l3_field.get("recv_ip_str", pkt.dst_ip)
            scapy_pkt[ARP].pdst = pkt.l3_field.get("send_ip_str", pkt.src_ip)

        return bytes(scapy_pkt)

    except Exception as e:
        logging.error(f"❌ synthesize_response failed: {e}")
        return None
