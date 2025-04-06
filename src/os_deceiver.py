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

from scapy.all import IP, TCP, UDP, ICMP, Ether, wrpcap, get_if_addr

import src.settings as settings
from src.settings import get_os_fingerprint, get_mac_address, CUSTOM_RULES
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

        logging.info(f"🎭 TTL/Window/IPID -> TTL={self.ttl}, Window={self.window}, IPID={self.ipid_mode}")
        logging.info(f"🧬 TCP Options: {self.tcp_options}")
        logging.info(f"🛡️ OS Deception initialized for '{self.os}' via NIC '{self.nic}'")

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
        self.ax.set_title("Live OS Deception Stats")
        self.ax.set_ylabel("Sent Packets")
        self.ax.set_ylim(0, max(values + [1]))

    def get_ip_id(self):
        if self.ipid_mode == "increment":
            self.ip_id_counter = (self.ip_id_counter + 1) % 65536
            return self.ip_id_counter
        elif self.ipid_mode == "random":
            return random.randint(0, 65535)
        elif self.ipid_mode == "zero":
            return 0
        return 0

    def os_deceive(self, timeout_minutes=5):
        from scapy.all import sniff

        timeout = datetime.now() + timedelta(minutes=timeout_minutes)

        def handle(pkt):
            try:
                packet = Packet(bytes(pkt))
                packet.interface = self.nic
                packet.unpack()
                proto = packet.l4 or packet.l3

                if not self.apply_custom_rules(packet, proto):
                    self.default_template_match(packet, proto)

            except Exception as e:
                logging.error(f"[Deceive] Error processing packet: {e}")

        logging.info("🚨 Starting OS deception loop...")
        sniff(iface=self.nic, store=False, prn=handle, timeout=timeout_minutes * 60)

    def apply_custom_rules(self, packet, proto):
        for rule in CUSTOM_RULES:
            if rule.get("proto") != proto.upper():
                continue

            if proto == "TCP":
                port = packet.l4_field.get("dest_port")
                flags = packet.l4_field.get("flags")
                if rule.get("port") and rule.get("port") != port:
                    continue
                if rule.get("flags") and rule["flags"] not in self.decode_tcp_flags(flags):
                    continue

            elif proto == "UDP":
                port = packet.l4_field.get("dest_port")
                if rule.get("port") and rule.get("port") != port:
                    continue

            elif proto == "ICMP":
                icmp_type = packet.l4_field.get("icmp_type")
                if rule.get("type") is not None and icmp_type != rule["type"]:
                    continue

            # Match found
            action = rule.get("action")
            log_msg = rule.get("log", f"⚙ Rule triggered: {rule}")
            logging.info(log_msg)

            if action == "drop":
                return True
            elif action == "rst":
                self.send_tcp_rst(packet)
                return True
            elif action == "icmp_unreachable":
                self.send_icmp_port_unreachable(packet)
                return True
            elif action == "template":
                return False  # allow template match below

        return False

    def decode_tcp_flags(self, flags):
        if flags is None:
            return []
        flag_map = {"F": 0x01, "S": 0x02, "R": 0x04, "P": 0x08, "A": 0x10, "U": 0x20, "E": 0x40, "C": 0x80}
        return [k for k, v in flag_map.items() if flags & v]

    def send_tcp_rst(self, pkt):
        ether = Ether(src=self.mac)
        ip = IP(src=pkt.l3_field["dest_IP_str"], dst=pkt.l3_field["src_IP_str"], ttl=self.ttl)
        tcp = TCP(
            sport=pkt.l4_field["dest_port"],
            dport=pkt.l4_field["src_port"],
            flags="R",
            seq=pkt.l4_field.get("ack_num", 0)
        )
        send_pkt = ether / ip / tcp
        self.protocol_stats["TCP"] += 1
        self.sent_packets.append(send_pkt)
        from scapy.all import sendp
        sendp(send_pkt, iface=self.nic, verbose=False)

    def send_icmp_port_unreachable(self, pkt):
        ether = Ether(src=self.mac)
        ip = IP(src=pkt.l3_field["dest_IP_str"], dst=pkt.l3_field["src_IP_str"], ttl=self.ttl)
        icmp = ICMP(type=3, code=3) / pkt.packet[:28]
        send_pkt = ether / ip / icmp
        self.protocol_stats["ICMP"] += 1
        self.sent_packets.append(send_pkt)
        from scapy.all import sendp
        sendp(send_pkt, iface=self.nic, verbose=False)

    def default_template_match(self, pkt, proto):
        try:
            templates = self.load_templates(proto)
            key, _ = gen_key(proto, pkt.packet)
            template = templates.get(key)
            if template:
                response = synthesize_response(pkt, template, ttl=self.ttl, window=self.window, deceiver=self)
                if response:
                    self.conn.sock.send(response)
                    self.protocol_stats[proto.upper()] += 1
                    self.sent_packets.append(response)
        except Exception as e:
            logging.warning(f"⚠ Template match failed: {e}")

    def load_templates(self, proto):
        path = os.path.join(self.os_record_path, f"{proto}_record.txt")
        if not os.path.exists(path):
            return {}
        with open(path) as f:
            raw = json.load(f)
        return {base64.b64decode(k): base64.b64decode(v) for k, v in raw.items()}
