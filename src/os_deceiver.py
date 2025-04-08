import os
import json
import base64
import logging
import socket
import struct
import time
import random
from datetime import datetime, timedelta
from collections import defaultdict
import threading
import matplotlib.pyplot as plt
import matplotlib.animation as animation

from scapy.all import IP, TCP, UDP, ICMP, Ether, wrpcap, send, get_if_addr, DNS, DNSQR, DNSRR

from src import settings
from src.settings import get_os_fingerprint, get_mac_address, CUSTOM_RULES, JA3_RULES
from src.Packet import Packet
from src.tcp import TcpConnect
from src.response import synthesize_response
from src.fingerprint_utils import gen_key
from src.ja3_extractor import extract_ja3_hash

UNMATCHED_LOG = os.path.join(settings.OS_RECORD_PATH, "unmatched_keys.log")

class OsDeceiver:
    def __init__(self, target_host: str, target_os: str, dest=None, nic: str = None):
        self.nic = nic or settings.NIC_PROBE
        self.mac = get_mac_address(self.nic)
        self.host = get_if_addr(self.nic)

        logging.info(f"🔌 Interface {self.nic} -> IP: {self.host}, MAC: {self.mac}")

        self.os = target_os
        self.dest = dest
        self.os_record_path = self.dest or os.path.join(settings.OS_RECORD_PATH, self.os)
        os.makedirs(self.os_record_path, exist_ok=True)

        self.conn = TcpConnect(self.host, nic=self.nic)

        os_template = get_os_fingerprint(self.os)
        self.ttl = os_template.get("ttl")
        self.window = os_template.get("window")
        self.ipid_mode = os_template.get("ipid", "increment")
        self.tcp_options = os_template.get("tcp_options", [])
        self.os_flags = {
            "df": os_template.get("df", False),
            "tos": os_template.get("tos", 0),
            "ecn": os_template.get("ecn", 0),
            "reserved": os_template.get("tcp_reserved", 0),
            "ip_options": os_template.get("ip_options", b"")
        }

        self.ip_id_counter = 0
        self.ip_state = {}
        self.timestamp_base = {}
        self.protocol_stats = defaultdict(int)
        self.sent_packets = []
        self.session_log = {}
        self.ja3_log = defaultdict(list)

        self._init_plot()

    def _init_plot(self):
        self.fig, self.ax = plt.subplots()
        self.ani = animation.FuncAnimation(self.fig, self._update_plot, interval=1000)
        threading.Thread(target=plt.show, daemon=True).start()

    def _update_plot(self, frame):
        self.ax.clear()
        labels = list(self.protocol_stats.keys())
        values = [self.protocol_stats[k] for k in labels]
        self.ax.bar(labels, values)
        self.ax.set_title("OS Deception Stats")
        self.ax.set_ylabel("Sent Packets")
        self.ax.set_ylim(0, max(values + [1]))

    def get_ip_id(self, src_ip):
        if self.ipid_mode == "increment":
            self.ip_id_counter += 1
            return self.ip_id_counter % 65536
        elif self.ipid_mode == "random":
            return random.randint(0, 65535)
        elif self.ipid_mode == "zero":
            return 0
        return random.randint(0, 65535)

    def os_deceive(self, timeout_minutes: int = 5):
        logging.info("🚦 Starting OS deception loop")
        templates = {ptype: self.load_file(ptype) for ptype in ["tcp", "icmp", "udp", "arp"]}
        timeout = datetime.now() + timedelta(minutes=timeout_minutes)

        while datetime.now() < timeout:
            try:
                raw, addr = self.conn.sock.recvfrom(65565)
                pkt = Packet(raw)
                pkt.interface = self.nic
                pkt.unpack()

                proto = pkt.l4 if pkt.l4 else pkt.l3
                src_ip = pkt.l3_field.get("src_IP_str")
                dst_ip = pkt.l3_field.get("dest_IP_str")
                dst_port = pkt.l4_field.get("dest_port", 0)
                flags = pkt.l4_field.get("flags", 0)
                tos = pkt.l3_field.get("TYPE_OF_SERVICE", 0)
                frag = pkt.l3_field.get("FRAGMENT_STATUS", 0)

                # JA3 detection
                if proto == "tcp" and dst_port in [443, 8443]:
                    ja3 = extract_ja3_hash(pkt.packet)
                    if ja3:
                        self.ja3_log[src_ip].append(ja3)
                        for rule in JA3_RULES:
                            if ja3 == rule.get("ja3"):
                                logging.info(f"🎯 JA3 match: {ja3} → {rule['action']}")
                                if rule['action'] == "drop":
                                    continue
                                elif rule['action'] == "template":
                                    template_name = rule.get("template_name")
                                    custom_template_path = os.path.join(self.os_record_path, f"{template_name}.bin")
                                    if os.path.exists(custom_template_path):
                                        with open(custom_template_path, "rb") as f:
                                            response = f.read()
                                            self.conn.send_packet(response)
                                            continue

                # DNS spoofing
                if proto == "udp" and dst_port == 53 and pkt.has_dns_query():
                    qname = pkt.dns_qname()
                    fake_ip = "1.2.3.4"  # could be dynamic
                    dns_resp = self.build_fake_dns_response(pkt, qname, fake_ip)
                    if dns_resp:
                        self.conn.send_packet(bytes(dns_resp))
                        self.sent_packets.append(bytes(dns_resp))
                        self.protocol_stats["DNS"] += 1
                        continue

                # Match CUSTOM_RULES
                for rule in CUSTOM_RULES:
                    match = rule.get("proto", "").lower() == proto
                    match &= rule.get("port", dst_port) == dst_port if "port" in rule else True
                    match &= rule.get("flags", "") in ["", chr(flags)] if proto == "tcp" else True
                    match &= rule.get("type", None) == pkt.l4_field.get("icmp_type") if proto == "icmp" else True
                    match &= rule.get("dscp", -1) == (tos >> 2) if "dscp" in rule else True
                    match &= rule.get("fragmented", False) == (frag != 0) if "fragmented" in rule else True
                    match &= rule.get("src_ip", "") == src_ip if "src_ip" in rule else True
                    if match:
                        logging.info(rule.get("log", f"Matched rule for {proto.upper()}"))
                        if rule["action"] == "drop":
                            continue
                        elif rule["action"] == "rst" and proto == "tcp":
                            self.send_tcp_rst(pkt)
                            continue
                        elif rule["action"] == "icmp_unreachable" and proto == "udp":
                            self.send_icmp_port_unreachable(pkt)
                            continue
                        elif rule["action"] == "template":
                            break  # fallthrough

                key, _ = gen_key(proto, pkt.packet)
                template = templates.get(proto, {}).get(key)

                if not template:
                    for k in templates.get(proto, {}):
                        if key.startswith(k[:16]):
                            template = templates[proto][k]
                            break

                if template:
                    response = synthesize_response(pkt, template, ttl=self.ttl, window=self.window, deceiver=self)
                    if response:
                        self.conn.send_packet(response)
                        self.sent_packets.append(response)
                        self.protocol_stats[proto.upper()] += 1
                        self.session_log.setdefault(src_ip, []).append({
                            "proto": proto,
                            "time": datetime.utcnow().isoformat(),
                            "action": "template"
                        })
                else:
                    if proto == "udp":
                        self.send_icmp_port_unreachable(pkt)
                    elif proto == "tcp":
                        self.send_tcp_rst(pkt)

            except Exception as e:
                logging.warning(f"❌ Error in os_deceive: {e}")

        self.export_sent_packets()
        self.export_session_log()
        self.export_ja3_log()

    def build_fake_dns_response(self, pkt, qname, fake_ip):
        try:
            ether = Ether(src=pkt.l2_field['dMAC'], dst=pkt.l2_field['sMAC'])
            ip = IP(src=pkt.l3_field['dest_IP_str'], dst=pkt.l3_field['src_IP_str'], ttl=self.ttl)
            udp = UDP(sport=53, dport=pkt.l4_field['src_port'])
            dns = DNS(id=pkt.dns_id(), qr=1, aa=1, rd=1, ra=1, qd=DNSQR(qname=qname), an=DNSRR(rrname=qname, rdata=fake_ip))
            return ether / ip / udp / dns
        except Exception as e:
            logging.warning(f"⚠️ Failed to build fake DNS: {e}")
            return None

    def send_tcp_rst(self, pkt):
        ip = IP(src=pkt.l3_field["dest_IP_str"], dst=pkt.l3_field["src_IP_str"], ttl=self.ttl)
        tcp = TCP(sport=pkt.l4_field["dest_port"], dport=pkt.l4_field["src_port"], flags="R", window=self.window)
        rst = Ether(src=self.mac) / ip / tcp
        self.conn.send_packet(bytes(rst))
        self.sent_packets.append(bytes(rst))
        self.protocol_stats["TCP"] += 1

    def send_icmp_port_unreachable(self, pkt):
        ip = IP(src=pkt.l3_field["dest_IP_str"], dst=pkt.l3_field["src_IP_str"], ttl=self.ttl)
        icmp = ICMP(type=3, code=3)
        inner = IP(pkt.packet[14:34]) / UDP(pkt.packet[34:42])
        reply = Ether(src=self.mac) / ip / icmp / bytes(inner)[:28]
        self.conn.send_packet(bytes(reply))
        self.sent_packets.append(bytes(reply))
        self.protocol_stats["ICMP"] += 1

    def load_file(self, proto):
        path = os.path.join(self.os_record_path, f"{proto}_record.txt")
        if not os.path.exists(path): return {}
        with open(path) as f:
            data = json.load(f)
        return {base64.b64decode(k): base64.b64decode(v) for k, v in data.items()}

    def export_sent_packets(self):
        path = os.path.join(self.os_record_path, "sent_os_responses.pcap")
        wrpcap(path, self.sent_packets)
        logging.info(f"📦 Saved PCAP: {path}")

    def export_session_log(self):
        path = os.path.join(self.os_record_path, "os_session_log.json")
        with open(path, "w") as f:
            json.dump(self.session_log, f, indent=2)
        logging.info(f"📝 Exported session log: {path}")

    def export_ja3_log(self):
        path = os.path.join(self.os_record_path, "ja3_log.json")
        with open(path, "w") as f:
            json.dump(self.ja3_log, f, indent=2)
        logging.info(f"🔎 Exported JA3 log: {path}")
