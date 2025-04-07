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

from scapy.all import IP, TCP, UDP, ICMP, Ether, wrpcap, send, get_if_addr

import src.settings as settings
from src.settings import get_os_fingerprint, get_mac_address, CUSTOM_RULES, JA3_RULES
from src.Packet import Packet
from src.tcp import TcpConnect
from src.response import synthesize_response
from src.ja3_extractor import extract_ja3_from_packet, match_ja3_rule
from src.fingerprint_utils import gen_key

debug_mode = os.environ.get("DEBUG", "0") == "1"
unmatched_log = os.path.join(settings.OS_RECORD_PATH, "unmatched_keys.log")

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
        if self.ipid_mode == "zero":
            return 0
        elif self.ipid_mode == "random":
            return random.randint(0, 65535)
        else:
            self.ip_id_counter = (self.ip_id_counter + 1) % 65536
            return self.ip_id_counter

    def get_tcp_options(self, src_ip, ts_echo=0):
        ts_val = int(time.time() * 1000) & 0xFFFFFFFF
        opts = []
        for opt in self.tcp_options:
            if opt.startswith("MSS"):
                val = int(opt.split("=")[1])
                opts.append(("MSS", val))
            elif opt == "SACK":
                opts.append(("SAckOK", b""))
            elif opt == "TS":
                opts.extend([("NOP", None), ("NOP", None), ("Timestamp", (ts_val, ts_echo))])
            elif opt.startswith("WS"):
                val = int(opt.split("=")[1])
                opts.append(("WScale", val))
            elif opt == "NOP":
                opts.append(("NOP", None))
        return opts

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
                dst_port = pkt.l4_field.get("dest_port", 0)

                ja3 = extract_ja3_from_packet(pkt) if proto == "tcp" else None
                if ja3:
                    rule = match_ja3_rule(ja3)
                    if rule:
                        logging.info(rule.get("log", "🎭 Matched JA3 rule"))
                        if rule["action"] == "drop":
                            continue
                        elif rule["action"] == "tls_hello":
                            resp = synthesize_response(pkt, b"", ttl=self.ttl, window=self.window, deceiver=self)
                            if resp:
                                self.conn.send_packet(resp)
                                self.protocol_stats[proto.upper()] += 1
                                continue

                key, _ = gen_key(proto, pkt.packet)
                template = templates.get(proto, {}).get(key)
                if not template:
                    for k in templates.get(proto, {}):
                        if key.startswith(k[:16]):
                            template = templates[proto][k]
                            break

                if template:
                    resp = synthesize_response(pkt, template, ttl=self.ttl, window=self.window, deceiver=self)
                    if resp:
                        self.conn.send_packet(resp)
                        self.sent_packets.append(resp)
                        self.protocol_stats[proto.upper()] += 1
                        self.session_log.setdefault(src_ip, []).append({
                            "proto": proto,
                            "time": datetime.utcnow().isoformat(),
                            "action": "template"
                        })
                elif proto == "udp" and pkt.l4_field.get("dest_port") == 53:
                    dns_resp = synthesize_response(pkt, b"", deceiver=self)
                    if dns_resp:
                        self.conn.send_packet(dns_resp)
                elif proto == "tcp":
                    self.send_tcp_rst(pkt)

            except Exception as e:
                logging.warning(f"❌ Error in os_deceive: {e}")

        self.export_sent_packets()
        self.export_session_log()

    def send_tcp_rst(self, pkt):
        ip = IP(src=pkt.l3_field["dest_IP_str"], dst=pkt.l3_field["src_IP_str"], ttl=self.ttl)
        tcp = TCP(sport=pkt.l4_field["dest_port"], dport=pkt.l4_field["src_port"], flags="R", window=self.window)
        rst = Ether(src=self.mac) / ip / tcp
        self.conn.send_packet(bytes(rst))
        self.sent_packets.append(bytes(rst))
        self.protocol_stats["TCP"] += 1

    def load_file(self, proto):
        path = os.path.join(self.os_record_path, f"{proto}_record.txt")
        if not os.path.exists(path):
            return {}
        with open(path, "r") as f:
            data = json.load(f)
        return {base64.b64decode(k): base64.b64decode(v) for k, v in data.items()}

    def export_sent_packets(self):
        pcap_path = os.path.join(self.os_record_path, "sent_os_responses.pcap")
        wrpcap(pcap_path, self.sent_packets)
        logging.info(f"📦 Exported pcap: {pcap_path}")

    def export_session_log(self):
        json_path = os.path.join(self.os_record_path, "os_session_log.json")
        with open(json_path, "w") as f:
            json.dump(self.session_log, f, indent=2)
        logging.info(f"📝 Session log saved: {json_path}")
