from scapy.all import Ether, IP, TCP, UDP, ICMP, ARP
import logging
import random

def synthesize_response(pkt, template: bytes, ttl: int = 64, window: int = 8192, deceiver=None) -> bytes:
    try:
        scapy_pkt = Ether(template)

        # Handle IP-based responses
        if IP in scapy_pkt:
            scapy_pkt[IP].dst = pkt.l3_field.get("src_IP_str", pkt.src_ip)
            scapy_pkt[IP].src = pkt.l3_field.get("dest_IP_str", pkt.dst_ip)
            scapy_pkt[IP].ttl = ttl
            scapy_pkt[IP].id = deceiver.get_ip_id(pkt.src_ip) if deceiver else random.randint(0, 65535)

            # TOS/ECN
            tos_val = getattr(deceiver, 'tos', 0) if deceiver else 0
            scapy_pkt[IP].tos = tos_val

            # DF bit
            df_bit = getattr(deceiver, 'os_flags', {}).get("df", False) if deceiver else False
            scapy_pkt[IP].flags = 'DF' if df_bit else 0

            del scapy_pkt[IP].chksum  # Force IP checksum recalculation

        # TCP spoofing
        if TCP in scapy_pkt:
            scapy_pkt[TCP].sport = pkt.l4_field.get("dest_port", 1234)
            scapy_pkt[TCP].dport = pkt.l4_field.get("src_port", 1234)
            scapy_pkt[TCP].seq = pkt.l4_field.get("ack_num", random.randint(0, 2**32-1))
            scapy_pkt[TCP].ack = pkt.l4_field.get("seq", 0) + 1
            scapy_pkt[TCP].flags = "SA"
            scapy_pkt[TCP].window = window

            # TCP Options from template
            if deceiver:
                src_ip_str = pkt.l3_field.get("src_IP_str", pkt.src_ip)
                ts_echo = pkt.l4_field.get("option_field", {}).get("ts_val", 0)
                scapy_pkt[TCP].options = deceiver.get_tcp_options(src_ip_str, ts_echo=ts_echo)

            del scapy_pkt[TCP].chksum

        # UDP spoofing
        if UDP in scapy_pkt:
            scapy_pkt[UDP].sport = pkt.l4_field.get("dest_port", 1234)
            scapy_pkt[UDP].dport = pkt.l4_field.get("src_port", 1234)
            del scapy_pkt[UDP].chksum

        # ICMP spoofing
        if ICMP in scapy_pkt:
            scapy_pkt[ICMP].type = 0  # Echo reply
            del scapy_pkt[ICMP].chksum

        # ARP spoofing
        if ARP in scapy_pkt:
            scapy_pkt[ARP].op = 2  # ARP reply
            scapy_pkt[ARP].psrc = pkt.l3_field.get("recv_ip_str", pkt.dst_ip)
            scapy_pkt[ARP].pdst = pkt.l3_field.get("send_ip_str", pkt.src_ip)

        return bytes(scapy_pkt)

    except Exception as e:
        logging.error(f"❌ synthesize_response failed: {e}")
        return None
