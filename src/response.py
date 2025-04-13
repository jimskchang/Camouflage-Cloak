# src/response.py

import logging
import random
import time
from ipaddress import ip_address, ip_network

from scapy.all import Ether, IP, TCP, UDP, ICMP
from dnslib import DNSRecord, QTYPE, RR, A

from src.ja3_extractor import extract_ja3, match_ja3_rule
from src.settings import JA3_RULES

EXCLUDE_SOURCES = [
    ip_network("192.168.10.0/24"),
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

        proto = pkt.l4

        # JA3-based handling
        if proto == "tcp":
            ja3 = extract_ja3_from_packet(pkt)
            rule = match_ja3_rule(ja3)
            if rule:
                logging.info(rule.get("log", "🎭 Matched JA3 rule"))
                if rule["action"] == "drop":
                    return None
                elif rule["action"] == "tls_hello":
                    return synthesize_tls_server_hello(pkt)

        # DNS spoof (UDP port 53)
        if proto == "udp" and pkt.l4_field.get("dest_port") == 53:
            return synthesize_dns_response(pkt)

        # Unpack template-based fields
        src_mac = pkt.l2_field.get("sMAC")
        dst_mac = pkt.l2_field.get("dMAC")
        src_ip = pkt.l3_field.get("src_IP")
        dst_ip = pkt.l3_field.get("dest_IP")

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
            logging.warning(f"❓ Unsupported L4 protocol in template: {proto}")
            return None

        if deceiver and hasattr(deceiver, 'simulate_delay'):
            try:
                delay = deceiver.simulate_delay(pkt)
                if delay > 0:
                    logging.debug(f"⏱️ Injecting delay: {delay:.3f}s")
                    time.sleep(delay)
            except Exception as e:
                logging.warning(f"⚠️ simulate_delay error: {e}")

        return bytes(ether / ip / l4_layer)

    except Exception as e:
        logging.error(f"❌ synthesize_response failed: {e}")
        return None


def synthesize_dns_response(pkt, spoof_ip="1.2.3.4"):
    try:
        payload = pkt.l4_field.get("raw_payload", b"")
        dns = DNSRecord.parse(payload)
        qname = str(dns.q.qname)
        qtype = QTYPE[dns.q.qtype]
        logging.debug(f"🌐 Spoofing DNS A Response for {qname} (type {qtype})")

        reply = DNSRecord(dns)
        reply.header.qr = 1
        reply.add_answer(RR(qname, QTYPE.A, rdata=A(spoof_ip), ttl=60))

        ether = Ether(src=pkt.l2_field['dMAC'], dst=pkt.l2_field['sMAC'])
        ip = IP(src=pkt.l3_field['dest_IP_str'], dst=pkt.l3_field['src_IP_str'], ttl=64)
        udp = UDP(sport=53, dport=pkt.l4_field['src_port'], len=0)

        return bytes(ether / ip / udp / bytes(reply.pack()))
    except Exception as e:
        logging.warning(f"⚠️ DNS spoof error: {e}")
        return None


def synthesize_tls_server_hello(pkt):
    try:
        ether = Ether(src=pkt.l2_field['dMAC'], dst=pkt.l2_field['sMAC'])
        ip = IP(src=pkt.l3_field['dest_IP_str'], dst=pkt.l3_field['src_IP_str'], ttl=64)
        tcp = TCP(
            sport=pkt.l4_field['dest_port'],
            dport=pkt.l4_field['src_port'],
            flags="PA",
            seq=pkt.l4_field.get("ack_num", 0),
            ack=pkt.l4_field.get("seq", 0) + len(pkt.l4_field.get("raw_payload", b"")),
            window=8192
        )

        tls_server_hello = bytes.fromhex(
            "160303003a020000360303"
            "11223344556677889900aabbccddeeff"
            "20" + "00" * 32 +
            "c02f" +
            "00" +
            "0000"
        )
        return bytes(ether / ip / tcp / tls_server_hello)
    except Exception as e:
        logging.error(f"❌ TLS ServerHello spoof failed: {e}")
        return None
