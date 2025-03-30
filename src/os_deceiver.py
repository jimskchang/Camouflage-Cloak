import os
import json
import base64
import logging
import socket
import struct
import time
import random
from datetime import datetime, timedelta

from scapy.all import IP, TCP, ICMP, Ether

import src.settings as settings
from src.settings import get_os_fingerprint
from src.Packet import Packet
from src.tcp import TcpConnect
from src.response import synthesize_response

DEBUG_MODE = os.environ.get("DEBUG", "0") == "1"
UNMATCHED_LOG = os.path.join(settings.OS_RECORD_PATH, "unmatched_keys.log")

def gen_key(proto: str, packet: bytes):
    if proto == 'tcp':
        return gen_tcp_key(packet)
    elif proto == 'icmp':
        return gen_icmp_key(packet)
    elif proto == 'udp':
        return gen_udp_key(packet)
    elif proto == 'arp':
        return gen_arp_key(packet)
    return b'', None

def gen_tcp_key(packet: bytes):
    try:
        ip_header = packet[14:34]
        tcp_header = packet[34:54]
        src_port, dest_port, seq, ack_num, offset_flags = struct.unpack('!HHLLH', tcp_header[:14])
        offset = (offset_flags >> 12) * 4
        payload = packet[54:54+offset-20]
        ip_key = ip_header[:8] + b'\x00' * 8
        tcp_key = struct.pack('!HHLLH', 0, dest_port, 0, 0, offset_flags) + tcp_header[14:20]
        return ip_key + tcp_key + payload, None
    except Exception as e:
        logging.warning(f"⚠️ gen_tcp_key failed: {e}")
        return b'', None

def gen_udp_key(packet: bytes):
    try:
        ip_header = packet[14:34]
        udp_header = packet[34:42]
        payload = packet[42:]
        ip_key = ip_header[:8] + b'\x00' * 8
        udp_key = struct.pack('!HHH', 0, 0, 8) + b'\x00\x00'
        return ip_key + udp_key + payload, None
    except Exception as e:
        logging.warning(f"⚠️ gen_udp_key failed: {e}")
        return b'', None

def gen_icmp_key(packet: bytes):
    try:
        ip_header = packet[14:34]
        icmp_header = packet[34:42]
        ip_key = ip_header[:8] + b'\x00' * 8
        icmp_type, code, _, _, _ = struct.unpack('!BBHHH', icmp_header)
        icmp_key = struct.pack('!BBHHH', icmp_type, code, 0, 0, 0)
        return ip_key + icmp_key, None
    except Exception as e:
        logging.warning(f"⚠️ gen_icmp_key failed: {e}")
        return b'', None

def gen_arp_key(packet: bytes):
    try:
        arp_header = packet[14:42]
        fields = struct.unpack('!HHBBH6s4s6s4s', arp_header)
        key = struct.pack('!HHBBH6s4s6s4s',
                          fields[0], fields[1], fields[2], fields[3], fields[4],
                          b'\x00'*6, b'\x00'*4, b'\x00'*6, b'\x00'*4)
        return key, None
    except Exception as e:
        logging.warning(f"⚠️ gen_arp_key failed: {e}")
        return b'', None

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
        self.ip_id_counter = 0
        self.timestamp_base = {}

    def get_ip_id(self, ip: str = "") -> int:
        if self.ipid_mode == "increment":
            self.ip_id_counter = (self.ip_id_counter + 1) % 65536
            return self.ip_id_counter
        elif self.ipid_mode == "random":
            return random.randint(0, 65535)
        return 0

    def get_timestamp(self, ip: str):
        now = time.time()
        if ip not in self.timestamp_base:
            base = int(now - random.uniform(1, 10))
            self.timestamp_base[ip] = base
        drifted = int((now - self.timestamp_base[ip]) * 1000)
        return drifted

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

    def os_deceive(self, timeout_minutes: int = 5):
        logging.info("🌀 Starting OS deception loop...")
        templates = {ptype: self.load_file(ptype) for ptype in ["tcp", "icmp", "udp", "arp"]}
        timeout = datetime.now() + timedelta(minutes=timeout_minutes)

        while datetime.now() < timeout:
            try:
                raw, addr = self.conn.sock.recvfrom(65565)
                ip_str = addr[0]
                pkt = Packet(raw)
                pkt.interface = self.nic
                pkt.unpack()

                proto = pkt.l4 if pkt.l4 else pkt.l3
                key, _ = gen_key(proto, pkt.packet)
                template = templates.get(proto, {}).get(key)

                if template:
                    response = synthesize_response(pkt, template, ttl=self.ttl, window=self.window, deceiver=self)
                    if response:
                        self.conn.sock.send(response)
                        logging.info(f"📤 Sent {proto.upper()} response to {ip_str}")
                else:
                    logging.warning(f"⚠️ No template for {proto.upper()} key")

            except Exception as e:
                logging.error(f"❌ Deception loop error: {e}")

    def load_file(self, proto: str):
        path = os.path.join(self.os_record_path, f"{proto}_record.txt")
        result = {}
        if os.path.exists(path):
            with open(path, "r") as f:
                data = json.load(f)
                for k, v in data.items():
                    try:
                        key = base64.b64decode(k.encode())
                        val = base64.b64decode(v.encode())
                        result[key] = val
                    except Exception as e:
                        logging.warning(f"⚠️ Failed to decode {proto} template: {e}")
        return result
