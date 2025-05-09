# src/os_deceiver.py

import os
import json
import time
import socket
import random
import logging
import threading
from datetime import datetime, timedelta
from collections import defaultdict

import matplotlib.pyplot as plt
import matplotlib.animation as animation
from scapy.all import IP, TCP, UDP, ICMP, Ether, wrpcap, get_if_addr

from src.settings import get_os_fingerprint, get_mac_address, CUSTOM_RULES
from src.Packet import Packet
from src.tcp import TcpConnect
from src.response import synthesize_response, export_ja3_observed
from src.fingerprint_utils import gen_key
from src.ja3_extractor import extract_ja3, match_ja3_rule
from src import l7_tracker

UNMATCHED_LOG = os.path.join(os.path.dirname(__file__), "..", "os_record", "unmatched_keys.log")


class OsDeceiver:
    def __init__(self, target_host, target_os, dest=None, nic=None, replay=False, interactive=False, enable_dns=False, enable_ja3=False):
        self.nic = nic
        self.mac = get_mac_address(nic)
        self.host = get_if_addr(nic)
        self.dest = dest or os.path.join("os_record", target_os)
        os.makedirs(self.dest, exist_ok=True)

        self.conn = TcpConnect(self.host, nic=self.nic)
        self.os = target_os
        self.replay = replay
        self.interactive = interactive
        self.enable_dns = enable_dns
        self.enable_ja3 = enable_ja3
        self.ja3_log = {}

        os_template = get_os_fingerprint(self.os)
        self.ttl = os_template.get("ttl", 64)
        self.window = os_template.get("window", 8192)
        self.ipid_mode = os_template.get("ipid", "increment")
        self.tcp_options = os_template.get("tcp_options", [])
        self.os_flags = {
            "df": os_template.get("df", False),
            "tos": os_template.get("tos", 0),
            "ecn": os_template.get("ecn", 0),
            "reserved": os_template.get("tcp_reserved", 0),
            "ip_options": os_template.get("ip_options", b""),
        }

        self.ip_state = {}
        self.sent_packets = []
        self.session_log = {}
        self.protocol_stats = defaultdict(int)

        self._init_plot()

    def _init_plot(self):
        self.fig, self.ax = plt.subplots()
        self.ani = animation.FuncAnimation(self.fig, self._update_plot, interval=1000)
        threading.Thread(target=plt.show, daemon=True).start()

    def _update_plot(self, frame):
        self.ax.clear()
        labels = list(self.protocol_stats)
        values = [self.protocol_stats[k] for k in labels]
        self.ax.bar(labels, values)
        self.ax.set_title("OS Deception Stats")
        self.ax.set_ylabel("Sent Packets")
        self.ax.set_ylim(0, max(values + [1]))

    def os_deceive(self, timeout_minutes=5):
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
                flags = pkt.l4_field.get("flags", 0)
                tos = pkt.l3_field.get("TYPE_OF_SERVICE", 0)
                frag = pkt.l3_field.get("FRAGMENT_STATUS", 0)

                # JA3 Fingerprint Check
                ja3_hash = None
                if self.enable_ja3 and proto == "tcp" and dst_port == 443:
                    ja3_hash = extract_ja3(pkt.packet)
                    if ja3_hash:
                        self.ja3_log.setdefault(src_ip, []).append(ja3_hash)
                        rule = match_ja3_rule(ja3_hash)
                        if rule:
                            logging.info(rule.get("log", f"[JA3] Matched: {ja3_hash}"))
                            if rule["action"] == "drop":
                                continue
                            elif rule["action"] == "template":
                                template_path = os.path.join(self.dest, f"ja3_{rule['template_name']}.bin")
                                if os.path.exists(template_path):
                                    with open(template_path, "rb") as f:
                                        tls_response = f.read()
                                    self.conn.send_packet(tls_response)
                                    self.protocol_stats["JA3"] += 1
                                    continue

                # Match Custom Rules
                for rule in CUSTOM_RULES:
                    match = rule.get("proto", "").lower() == proto
                    match &= rule.get("port", dst_port) == dst_port if "port" in rule else True
                    match &= rule.get("flags", "") in ["", chr(flags)] if proto == "tcp" else True
                    match &= rule.get("type") == pkt.l4_field.get("icmp_type") if proto == "icmp" else True
                    match &= rule.get("dscp", -1) == (tos >> 2) if "dscp" in rule else True
                    match &= rule.get("fragmented", False) == (frag != 0) if "fragmented" in rule else True
                    match &= rule.get("src_ip", "") == src_ip if "src_ip" in rule else True

                    if match:
                        logging.info(rule.get("log", f"[RULE] Match for {proto.upper()}"))
                        if rule["action"] == "drop":
                            continue
                        elif rule["action"] == "rst" and proto == "tcp":
                            self.send_tcp_rst(pkt)
                            continue
                        elif rule["action"] == "icmp_unreachable" and proto == "udp":
                            self.send_icmp_port_unreachable(pkt)
                            continue
                        elif rule["action"] == "template":
                            break

                # Template Match
                key, _ = gen_key(proto, pkt.packet)
                template = templates.get(proto, {}).get(key)

                if not template:
                    for k in templates.get(proto, {}):
                        if key.startswith(k[:16]):
                            template = templates[proto][k]
                            logging.debug(f"🔍 Fuzzy match hit: {proto.upper()}")
                            break

                if template:
                    response = synthesize_response(pkt, template, ttl=self.ttl, window=self.window, deceiver=self)
                    if response:
                        self.conn.sock.send(response)
                        self.sent_packets.append(response)
                        self.protocol_stats[proto.upper()] += 1
                        self.session_log.setdefault(src_ip, []).append({
                            "proto": proto,
                            "time": datetime.utcnow().isoformat(),
                            "action": "template"
                        })

                        # L7 Logging
                        banner_type = pkt.l4_field.get("http_banner_type")
                        user_agent = pkt.l4_field.get("user_agent")
                        if banner_type:
                            l7_tracker.log_http_banner(src_ip, ja3_hash, banner_type, user_agent)

                else:
                    if proto == "udp":
                        self.send_icmp_port_unreachable(pkt)
                    elif proto == "tcp":
                        self.send_tcp_rst(pkt)

            except Exception as e:
                logging.warning(f"❌ os_deceive error: {e}")

        self.export_sent_packets()
        self.export_session_log()
        export_ja3_observed()
        l7_tracker.export()

    def send_tcp_rst(self, pkt):
        ip = IP(src=pkt.l3_field["dest_IP_str"], dst=pkt.l3_field["src_IP_str"], ttl=self.ttl)
        tcp = TCP(sport=pkt.l4_field["dest_port"], dport=pkt.l4_field["src_port"], flags="R", window=self.window)
        rst = Ether(src=self.mac) / ip / tcp
        self.conn.sock.send(bytes(rst))
        self.sent_packets.append(bytes(rst))
        self.protocol_stats["TCP"] += 1

    def send_icmp_port_unreachable(self, pkt):
        ip = IP(src=pkt.l3_field["dest_IP_str"], dst=pkt.l3_field["src_IP_str"], ttl=self.ttl)
        icmp = ICMP(type=3, code=3)
        inner = IP(pkt.packet[14:34]) / UDP(pkt.packet[34:42])
        reply = Ether(src=self.mac) / ip / icmp / bytes(inner)[:28]
        self.conn.sock.send(bytes(reply))
        self.sent_packets.append(bytes(reply))
        self.protocol_stats["ICMP"] += 1

    def load_file(self, proto: str) -> dict:
        path = os.path.join(self.dest, f"{proto}_record.txt")
        if not os.path.exists(path):
            return {}
        try:
            with open(path, "r") as f:
                return {bytes.fromhex(k): bytes.fromhex(v) for k, v in json.load(f).items()}
        except Exception as e:
            logging.warning(f"⚠️ Failed to load template {proto}: {e}")
            return {}

    def export_sent_packets(self):
        path = os.path.join(self.dest, "sent_os_responses.pcap")
        wrpcap(path, self.sent_packets)
        logging.info(f"📦 Sent packet PCAP exported: {path}")

    def export_session_log(self):
        path = os.path.join(self.dest, "os_session_log.json")
        with open(path, "w") as f:
            json.dump(self.session_log, f, indent=2)
        logging.info(f"📝 Session log exported: {path}")
