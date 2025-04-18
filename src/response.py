import logging
import random
import time
import json
from ipaddress import ip_address, ip_network
from scapy.all import Ether, IP, TCP, UDP, ICMP
from dnslib import DNSRecord, QTYPE, RR, A
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from datetime import datetime, timedelta

from src.ja3_extractor import extract_ja3, match_ja3_rule
from src.settings import JA3_RULES

EXCLUDE_SOURCES = [ip_network("192.168.10.0/24")]
JA3_OBSERVED_LOG = "ja3_observed.json"
JA3_OBSERVED = {}

HTTP_BANNERS = {
    "default": "HTTP/1.1 200 OK\r\nServer: Apache/2.4.41 (Unix)\r\nContent-Length: 13\r\n\r\nHello, World!",
    "ja3+chrome": "HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\nContent-Length: 17\r\n\r\nHello from Chrome!",
    "ja3+curl": "HTTP/1.1 200 OK\r\nServer: CamouflageHTTP/1.0\r\nContent-Length: 16\r\n\r\nHello curl user!"
}

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

        if proto == "tcp":
            # --- JA3 Fingerprint Handling ---
            ja3 = extract_ja3(pkt.packet)
            if ja3:
                JA3_OBSERVED.setdefault(src_ip_str, []).append(ja3)
                rule = match_ja3_rule(ja3)
                if rule:
                    logging.info(rule.get("log", "🎭 Matched JA3 rule"))
                    if rule["action"] == "drop":
                        return None
                    elif rule["action"] == "tls_hello":
                        return synthesize_tls_server_hello(pkt)

            # --- HTTP GET / Banner spoofing ---
            payload = pkt.l4_field.get("raw_payload", b"").decode(errors="ignore")
            if payload.startswith("GET") and (pkt.l4_field.get("dest_port") in [80, 8080]):
                ua = ""
                for line in payload.split("\r\n"):
                    if line.lower().startswith("user-agent"):
                        ua = line.split(":", 1)[-1].strip().lower()
                        break

                if "curl" in ua:
                    return synthesize_http_response(pkt, HTTP_BANNERS["ja3+curl"])
                elif "chrome" in ua:
                    return synthesize_http_response(pkt, HTTP_BANNERS["ja3+chrome"])
                else:
                    return synthesize_http_response(pkt, HTTP_BANNERS["default"])

        if proto == "udp" and pkt.l4_field.get("dest_port") == 53:
            return synthesize_dns_response(pkt)

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

def synthesize_http_response(pkt, banner):
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
        return bytes(ether / ip / tcp / banner.encode())
    except Exception as e:
        logging.error(f"❌ synthesize_http_response failed: {e}")
        return None

def synthesize_dns_response(pkt, spoof_ip="1.2.3.4"):
    try:
        payload = pkt.l4_field.get("raw_payload", b"")
        dns = DNSRecord.parse(payload)
        qname = str(dns.q.qname)
        qtype = QTYPE[dns.q.qtype] if dns.q.qtype in QTYPE else dns.q.qtype

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
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"California"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, u"San Francisco"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Camouflage Cloak"),
            x509.NameAttribute(NameOID.COMMON_NAME, u"tls-fuzz.local")
        ])
        cert = x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(
            key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(
            datetime.utcnow()).not_valid_after(datetime.utcnow() + timedelta(days=10)).sign(
            key, hashes.SHA256(), default_backend())

        cert_bytes = cert.public_bytes(serialization.Encoding.DER)
        tls_cert_record = b"\x16\x03\x03" + len(cert_bytes).to_bytes(2, 'big') + cert_bytes

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
        return bytes(ether / ip / tcp / tls_cert_record)

    except Exception as e:
        logging.error(f"❌ TLS ServerHello spoof failed: {e}")
        return None

def export_ja3_observed():
    try:
        with open(JA3_OBSERVED_LOG, "w") as f:
            json.dump(JA3_OBSERVED, f, indent=2)
        logging.info(f"📥 JA3 observed log saved: {JA3_OBSERVED_LOG}")
    except Exception as e:
        logging.warning(f"⚠️ Failed to save JA3 log: {e}")
     
     
