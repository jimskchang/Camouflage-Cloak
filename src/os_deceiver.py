import os
import json
import base64
import logging
import socket
import struct
import time
import random
from datetime import datetime, timedelta
from typing import Dict
from collections import defaultdict

from scapy.all import IP, TCP, ICMP, Ether

import src.settings as settings
from src.settings import get_os_fingerprint
from src.Packet import Packet
from src.tcp import TcpConnect
from src.response import synthesize_response
from src.fingerprint_utils import generateKey

DEBUG_MODE = os.environ.get("DEBUG", "0") == "1"
UNMATCHED_LOG = os.path.join(settings.OS_RECORD_PATH, "unmatched_keys.log")

class OsDeceiver:
    def __init__(self, target_host: str, target_os: str, dest=None, nic: str = None):
        self.host = target_host
        self.os = target_os
        self.nic = nic or settings.NIC_PROBE
        self.dest = dest
        self.os_record_path = self.dest or os.path.join(settings.OS_RECORD_PATH, self.os)

        if not os.path.exists(f"/sys/class/net/{self.nic}"):
            logging.error(f"❌ NIC '{self.nic}' not found.")
            raise ValueError(f"NIC '{self.nic}' does not exist.")

        try:
            with open(f"/sys/class/net/{self.nic}/address", "r") as f:
                mac = f.read().strip()
                logging.info(f"✅ Using MAC address {mac} for NIC '{self.nic}'")
        except Exception as e:
            logging.warning(f"⚠️ Unable to read MAC address: {e}")

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
        self.template_dict = defaultdict(dict)
        self.pair_dict = {}

        logging.info(f"🎭 TTL/Window/IPID -> TTL={self.ttl}, Window={self.window}, IPID={self.ipid_mode}")
        logging.info(f"🛡️ OS Deception initialized for '{self.os}' via NIC '{self.nic}'")
        logging.info(f"📁 Using OS template path: {self.os_record_path}")

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

    def os_deceive(self, timeout_minutes: int = 5):
        logging.info("🌀 Starting OS deception loop with Algorithm 5...")
        templates = {ptype: self.load_file(ptype) for ptype in ["tcp", "icmp", "udp", "arp"]}
        timeout = datetime.now() + timedelta(minutes=timeout_minutes)

        while datetime.now() < timeout:
            try:
                raw, addr = self.conn.sock.recvfrom(65565)
                pkt = Packet(raw)
                pkt.interface = self.nic
                pkt.unpack()

                proto = pkt.l4 if pkt.l4 else pkt.l3
                key = generateKey(pkt, proto.upper())

                if proto == "arp" and key in templates["arp"]:
                    rsp = Packet(templates["arp"][key])
                    rsp.l3_field.update({
                        "sender_mac": pkt.l2_field.get("dMAC"),
                        "receiver_mac": pkt.l2_field.get("sMAC"),
                        "sender_ip": pkt.l3_field.get("dest_IP"),
                        "recv_ip": pkt.l3_field.get("src_IP")
                    })
                    self.conn.sock.send(rsp.packet)

                elif proto == "tcp" and key in templates["tcp"]:
                    rsp = Packet(templates["tcp"][key])
                    rsp.l3_field.update({
                        "src_IP": pkt.l3_field.get("dest_IP"),
                        "dest_IP": pkt.l3_field.get("src_IP")
                    })
                    rsp.l4_field.update({
                        "src_port": pkt.l4_field.get("dest_port"),
                        "dest_port": pkt.l4_field.get("src_port"),
                        "seq": pkt.l4_field.get("ack_num"),
                        "ack_num": pkt.l4_field.get("seq") + 1
                    })
                    self.conn.sock.send(rsp.packet)

                elif proto == "udp" and key in templates["udp"]:
                    rsp = Packet(templates["udp"][key])
                    rsp.l3_field.update({
                        "src_IP": pkt.l3_field.get("dest_IP"),
                        "dest_IP": pkt.l3_field.get("src_IP")
                    })
                    self.conn.sock.send(rsp.packet)

                elif proto == "icmp" and key in templates["icmp"]:
                    rsp = Packet(templates["icmp"][key])
                    rsp.l3_field.update({
                        "src_IP": pkt.l3_field.get("dest_IP"),
                        "dest_IP": pkt.l3_field.get("src_IP")
                    })
                    rsp.l4_field.update({
                        "ID": pkt.l4_field.get("ID"),
                        "seq": pkt.l4_field.get("seq")
                    })
                    self.conn.sock.send(rsp.packet)

                else:
                    logging.debug(f"⚠️ No match for {proto.upper()} key {key[:16].hex()}... dropping")

            except Exception as e:
                logging.error(f"❌ Error in OS deception: {e}")

    def load_file(self, proto):
        filename = os.path.join(self.os_record_path, f"{proto}_record.txt")
        if not os.path.exists(filename):
            return {}
        with open(filename, "r") as f:
            data = json.load(f)
        return {base64.b64decode(k): base64.b64decode(v) for k, v in data.items()}
