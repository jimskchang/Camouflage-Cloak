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

from scapy.all import IP, TCP, ICMP, Ether, wrpcap, get_if_addr

import src.settings as settings
from src.settings import get_os_fingerprint, get_mac_address
from src.Packet import Packet
from src.tcp import TcpConnect
from src.response import synthesize_response
from src.fingerprint_utils import gen_key

DEBUG_MODE = os.environ.get("DEBUG", "0") == "1"
UNMATCHED_LOG = os.path.join(settings.OS_RECORD_PATH, "unmatched_keys.log")

class OsDeceiver:
    def __init__(self, target_host: str, target_os: str, dest=None, nic: str = None):
        self.nic = nic or settings.NIC_PROBE

        if not os.path.exists(f"/sys/class/net/{self.nic}"):
            logging.error(f"❌ NIC '{self.nic}' not found.")
            raise ValueError(f"NIC '{self.nic}' does not exist.")

        try:
            self.mac = get_mac_address(self.nic)
            self.host = get_if_addr(self.nic)
            logging.info(f"🔌 Interface {self.nic} -> IP: {self.host}, MAC: {self.mac}")
        except Exception as e:
            logging.error(f"❌ Failed to get IP/MAC for {self.nic}: {e}")
            raise

        self.os = target_os
        self.dest = dest
        self.os_record_path = self.dest or os.path.join(settings.OS_RECORD_PATH, self.os)
        os.makedirs(self.os_record_path, exist_ok=True)

        self.conn = TcpConnect(self.host, nic=self.nic)

        os_template = get_os_fingerprint(self.os)
        if not os_template:
            logging.error(f"❌ OS template '{self.os}' could not be loaded.")
            raise ValueError(f"Invalid OS template: {self.os}")

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
        self.template_dict = defaultdict(dict)
        self.pair_dict = {}

        logging.info(f"🎭 TTL/Window/IPID -> TTL={self.ttl}, Window={self.window}, IPID={self.ipid_mode}")
        logging.info(f"🧬 TCP Options: {self.tcp_options}")
        logging.info(f"🛡️ OS Deception initialized for '{self.os}' via NIC '{self.nic}'")
        logging.info(f"📁 Using OS template path: {self.os_record_path}")

        self._init_plot()

    def _init_plot(self):
        self.fig, self.ax = plt.subplots()
        self.line, = self.ax.plot([], [], lw=2)
        self.ani = animation.FuncAnimation(self.fig, self._update_plot, interval=1000, blit=False)
        threading.Thread(target=plt.show, daemon=True).start()

    def _update_plot(self, frame):
        self.ax.clear()
        labels = list(self.protocol_stats.keys())
        values = [self.protocol_stats[l] for l in labels]
        self.ax.bar(labels, values)
        self.ax.set_title("Live Deception Packet Count")
        self.ax.set_ylabel("Packets Sent")
        self.ax.set_ylim(0, max(values + [1]))

    def get_timestamp(self, ip: str):
        now = time.time()
        if ip not in self.timestamp_base:
            base = int(now - random.uniform(1, 10))
            self.timestamp_base[ip] = base
        drifted = int((now - self.timestamp_base[ip]) * 1000)
        return drifted

    def get_ip_id(self, ip: str = "") -> int:
        if self.ipid_mode == "increment":
            self.ip_id_counter = (self.ip_id_counter + 1) % 65536
            return self.ip_id_counter
        elif self.ipid_mode == "random":
            return random.randint(0, 65535)
        elif self.ipid_mode == "zero":
            return 0
        return 0

    def get_tcp_options(self, src_ip: str, ts_echo=0):
        options = []
        for opt in self.tcp_options:
            if opt.startswith("MSS="):
                options.append(("MSS", int(opt.split("=")[1])))
            elif opt.startswith("WS="):
                options.append(("WS", int(opt.split("=")[1])))
            elif opt == "TS":
                ts_val = self.get_timestamp(src_ip)
                options.append(("Timestamp", (ts_val, ts_echo)))
            elif opt == "SACK":
                options.append(("SAckOK", b""))
            elif opt == "NOP":
                options.append(("NOP", None))
        return options

    def match_custom_rules(self, pkt: Packet, proto: str) -> dict:
        for rule in settings.CUSTOM_RULES:
            if rule.get("proto", "").upper() != proto.upper():
                continue

            port = rule.get("port")
            if port and pkt.l4_field.get("dest_port") != port:
                continue

            flags = rule.get("flags")
            if flags:
                pkt_flags = pkt.l4_field.get("flags")
                if not pkt_flags or chr(pkt_flags) != flags:
                    continue

            if "tos" in rule:
                if pkt.l3_field.get("TYPE_OF_SERVICE") != rule["tos"]:
                    continue

            if "ecn" in rule:
                tos = pkt.l3_field.get("TYPE_OF_SERVICE", 0)
                pkt_ecn = tos & 0x03
                if pkt_ecn != rule["ecn"]:
                    continue

            if rule.get("frag_offset"):
                frag = pkt.l3_field.get("FRAGMENT_STATUS", 0)
                if frag == 0:
                    continue

            return rule
        return {}

    def os_deceive(self, timeout_minutes: int = 5):
        logging.info("🌀 Starting OS deception loop...")
        templates = {ptype: self.load_file(ptype) for ptype in ["tcp", "icmp", "udp", "arp"]}
        timeout = datetime.now() + timedelta(minutes=timeout_minutes)
        counter = 0

        while datetime.now() < timeout:
            try:
                raw, addr = self.conn.sock.recvfrom(65565)
                ip_str = addr[0]
                pkt = Packet(raw)
                pkt.interface = self.nic
                pkt.unpack()

                proto = pkt.l4 if pkt.l4 else pkt.l3
                self.track_ip_state(ip_str, proto)

                rule = self.match_custom_rules(pkt, proto)
                if rule:
                    action = rule.get("action")
                    log_msg = rule.get("log", f"📌 Custom rule matched: {rule}")
                    logging.info(log_msg)
                    if action == "drop":
                        continue
                    elif action == "icmp_unreachable":
                        self.send_icmp_port_unreachable(pkt)
                        continue
                    elif action == "rst":
                        self.send_tcp_rst(pkt)
                        continue

                key, _ = gen_key(proto, pkt.packet)
                template = templates.get(proto, {}).get(key)

                if not template:
                    for k in templates.get(proto, {}):
                        if key.startswith(k[:16]):
                            template = templates[proto][k]
                            logging.info(f"🔍 Fuzzy match hit for {proto.upper()} template")
                            break

                if not template:
                    default_key = f"default_{proto}_response".encode()
                    template = templates.get(proto, {}).get(default_key)
                    if template:
                        logging.info(f"✨ Using default {proto} fallback template")

                if template:
                    response = synthesize_response(pkt, template, ttl=self.ttl, window=self.window, deceiver=self)
                    if response:
                        self.conn.sock.send(response)
                        self.protocol_stats[proto.upper()] += 1
                        self.sent_packets.append(response)
                        counter += 1
                        logging.info(f"📤 Sent {proto.upper()} response #{counter}")
                    continue

                if proto == 'udp':
                    self.send_icmp_port_unreachable(pkt)
                elif proto == 'tcp':
                    self.send_tcp_rst(pkt)

                if settings.AUTO_LEARN_MISSING:
                    logging.info(f"🧠 Learning new {proto.upper()} template")
                    templates[proto][key] = pkt.packet
                    self.save_record(proto, templates[proto])
                elif DEBUG_MODE:
                    with open(UNMATCHED_LOG, "a") as f:
                        f.write(f"[{proto}] {key.hex()}\n")

            except Exception as e:
                logging.error(f"❌ Error in deception loop: {e}")

        self.export_state_log()
        self.export_sent_packets()

    def send_tcp_rst(self, pkt: Packet):
        pass

    def send_icmp_port_unreachable(self, pkt: Packet):
        pass

    def load_file(self, proto):
        filename = os.path.join(self.os_record_path, f"{proto}_record.txt")
        if not os.path.exists(filename):
            return {}
        with open(filename, "r") as f:
            data = json.load(f)
        return {base64.b64decode(k): base64.b64decode(v) for k, v in data.items()}

    def save_record(self, proto, data):
        filename = os.path.join(self.os_record_path, f"{proto}_record.txt")
        encoded = {
            base64.b64encode(k).decode(): base64.b64encode(v).decode()
            for k, v in data.items()
        }
        with open(filename, "w") as f:
            json.dump(encoded, f, indent=2)

    def export_state_log(self):
        state_file = os.path.join(self.os_record_path, "ip_state_log.json")
        try:
            with open(state_file, "w") as f:
                json.dump(self.ip_state, f, indent=2)
            logging.info(f"📝 Exported per-IP state log to {state_file}")
        except Exception as e:
            logging.warning(f"⚠ Failed to export IP state: {e}")

    def export_sent_packets(self):
        try:
            pcap_file = os.path.join(self.os_record_path, "sent_responses.pcap")
            wrpcap(pcap_file, self.sent_packets)
            logging.info(f"📦 Exported sent deception packets to {pcap_file}")
        except Exception as e:
            logging.error(f"❌ Failed to export PCAP: {e}")

    def track_ip_state(self, ip: str, proto: str):
        now = datetime.utcnow().isoformat()
        self.ip_state.setdefault(ip, {})[proto] = now
