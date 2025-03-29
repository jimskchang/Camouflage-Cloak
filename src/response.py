from scapy.all import Ether, IP, TCP, UDP, ICMP, ARP
import logging

def synthesize_response(pkt, template: bytes, ttl: int = 64, window: int = 8192) -> bytes:
    try:
        scapy_pkt = Ether(template)

        # Handle IP-based responses
        if IP in scapy_pkt:
            scapy_pkt[IP].dst = pkt.l3_field.get("src_IP_str", pkt.src_ip)
            scapy_pkt[IP].src = pkt.l3_field.get("dest_IP_str", pkt.dst_ip)
            scapy_pkt[IP].ttl = ttl
            del scapy_pkt[IP].chksum  # Force recalculation

        # TCP spoofing
        if TCP in scapy_pkt:
            scapy_pkt[TCP].sport = pkt.l4_field.get("dest_port", 1234)
            scapy_pkt[TCP].dport = pkt.l4_field.get("src_port", 1234)
            scapy_pkt[TCP].window = window
            scapy_pkt[TCP].flags = "SA"  # SYN+ACK default
            del scapy_pkt[TCP].chksum

        # UDP spoofing
        if UDP in scapy_pkt:
            scapy_pkt[UDP].sport = pkt.l4_field.get("dest_port", 1234)
            scapy_pkt[UDP].dport = pkt.l4_field.get("src_port", 1234)
            del scapy_pkt[UDP].chksum

        # ICMP spoofing
        if ICMP in scapy_pkt:
            scapy_pkt[ICMP].type = 0  # Echo Reply
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
