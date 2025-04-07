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

from src.settings import get_os_fingerprint, get_mac_address, CUSTOM_RULES, JA3_RULES
from src.tcp import TcpConnect
from src.response import synthesize_response
from src.fingerprint_utils import gen_key
from src.Packet import Packet

class OsDeceiver:
    def __init__(self, target_host, target_os, dest=None, nic=None):
        self.nic = nic
        self.mac = get_mac_address(nic)
        self.host = get_if_addr(nic)
        self.os = target_os
        self.dest = dest or os.path.join("os_record", self.os)
        os.makedirs(self.dest, exist_ok=True)

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
        self.ja3_log = {}

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
        if self.ipid_mode == "zero": return 0
        if self.ipid_mode == "random": return random.randint(0, 65535)
        self.ip_id_counter = (self.ip_id_counter + 1) % 65536
        return self.ip_id_counter

    def get_tcp_options(self, src_ip, ts_echo=0):
        options = []
        for opt in self.tcp_options:
            if opt.startswith("MSS"): options.append(("MSS", int(opt.split("=")[1])))
            elif opt == "SACK": options.append(("SAckOK", b""))
            elif opt == "TS":
                tsval = int(time.time() * 1000) & 0xFFFFFFFF
                options.extend([("NOP", None), ("NOP", None), ("Timestamp", (tsval, ts_echo))])
            elif opt.startswith("WS"): options.append(("WScale", int(opt.split("=")[1])))
            else: options.append((opt, None))
        return options

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

                proto = pkt.l4 or pkt.l3
                src_ip = pkt.l3_field.get("src_IP_str")
                dst_port = pkt.l4_field.get("dest_port", 0)
                flags = pkt.l4_field.get("flags", 0)
                tos = pkt.l3_field.get("TYPE_OF_SERVICE", 0)
                frag = pkt.l3_field.get("FRAGMENT_STATUS", 0)

                # JA3 detection hook
                ja3_fp = pkt.l7_field.get("ja3") if pkt.l7_field else None
                if ja3_fp:
                    self.ja3_log.setdefault(src_ip, []).append(ja3_fp)
                    for rule in JA3_RULES:
                        if rule.get("ja3") == ja3_fp:
                            logging.info(rule.get("log", "🎯 JA3 matched"))
                            if rule["action"] == "drop": continue
                            if rule["action"] == "template":
                                custom_template = self.load_custom_template(rule["template_name"])
                                response = synthesize_response(pkt, custom_template, ttl=self.ttl, window=self.window, deceiver=self)
                                if response:
                                    self.conn.send_packet(response)
                                    continue

                # Custom Rules
                for rule in CUSTOM_RULES:
                    if rule.get("proto", "").lower() != proto: continue
                    if "port" in rule and rule["port"] != dst_port: continue
                    if "flags" in rule and rule["flags"] != chr(flags): continue
                    if "dscp" in rule and rule["dscp"] != (tos >> 2): continue
                    if "fragmented" in rule and rule["fragmented"] != (frag != 0): continue
                    if "src_ip" in rule and rule["src_ip"] != src_ip: continue

                    logging.info(rule.get("log", f"🔧 Custom rule matched for {proto.upper()}"))
                    if rule["action"] == "drop": continue
                    elif rule["action"] == "rst" and proto == "tcp":
                        self.send_tcp_rst(pkt)
                        continue
                    elif rule["action"] == "icmp_unreachable" and proto == "udp":
                        self.send_icmp_port_unreachable(pkt)
                        continue
                    elif rule["action"] == "template":
                        break

                # L7 marker simulation
                if pkt.l7_field.get("dns_query"):
                    logging.info(f"🌐 DNS Query spoofed for {pkt.l7_field['dns_query']}")
                if pkt.l7_field.get("http_user_agent"):
                    logging.info(f"🌍 HTTP UA: {pkt.l7_field['http_user_agent']}")

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
                    if proto == "udp": self.send_icmp_port_unreachable(pkt)
                    elif proto == "tcp": self.send_tcp_rst(pkt)

            except Exception as e:
                logging.warning(f"❌ Deception error: {e}")

        self.export_sent_packets()
        self.export_session_log()
        self.export_ja3_log()

    def send_tcp_rst(self, pkt):
        rst = self.conn.build_tcp_rst(pkt)
        self.conn.send_packet(rst)
        self.sent_packets.append(rst)
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
        path = os.path.join(self.dest, f"{proto}_record.txt")
        if not os.path.exists(path): return {}
        with open(path) as f:
            data = json.load(f)
        return {base64.b64decode(k): base64.b64decode(v) for k, v in data.items()}

    def load_custom_template(self, name):
        path = os.path.join(self.dest, f"{name}.bin")
        if not os.path.exists(path): return None
        with open(path, "rb") as f: return f.read()

    def export_sent_packets(self):
        path = os.path.join(self.dest, "sent_os_responses.pcap")
        wrpcap(path, self.sent_packets)
        logging.info(f"📦 OS responses saved: {path}")

    def export_session_log(self):
        path = os.path.join(self.dest, "os_session_log.json")
        with open(path, "w") as f:
            json.dump(self.session_log, f, indent=2)
        logging.info(f"📝 OS session log saved: {path}")

    def export_ja3_log(self):
        if not self.ja3_log: return
        path = os.path.join(self.dest, "ja3_log.json")
        with open(path, "w") as f:
            json.dump(self.ja3_log, f, indent=2)
        logging.info(f"🔒 JA3 fingerprints logged: {path}")
