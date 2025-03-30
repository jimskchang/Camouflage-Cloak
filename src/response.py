from scapy.all import Ether, IP, TCP, UDP, ICMP, ARP
import logging

def synthesize_response(pkt, template: bytes, ttl: int = 64, window: int = 8192, deceiver=None) -> bytes:
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

            # Add TCP Options with Timestamp if deceiver is provided
            if deceiver:
                src_ip = pkt.l3_field.get("src_IP")
                if src_ip:
                    src_ip_str = pkt.l3_field.get("src_IP_str", pkt.src_ip)
                    ts_val = deceiver.get_timestamp(src_ip_str)
                    ts_echo = pkt.tcp_options.get("TSval", 0) if hasattr(pkt, 'tcp_options') else 0
                    scapy_pkt[TCP].options = [
                        ("MSS", 1460),
                        ("NOP", None),
                        ("WS", 7),
                        ("NOP", None),
                        ("NOP", None),
                        ("Timestamp", (ts_val, ts_echo)),
                        ("SAckOK", b"")
                    ]

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
