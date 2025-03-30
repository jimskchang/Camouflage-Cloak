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

# --- Key Normalization Helpers ---
def gen_key(proto: str, packet: bytes):
    try:
        if proto == 'tcp':
            ip_header = packet[14:34]
            tcp_header = packet[34:54]
            src_port, dest_port, seq, ack_num, offset_flags = struct.unpack('!HHLLH', tcp_header[:14])
            offset = (offset_flags >> 12) * 4
            payload = packet[54:54+offset-20]
            ip_key = ip_header[:8] + b'\x00' * 8
            tcp_key = struct.pack('!HHLLH', 0, dest_port, 0, 0, offset_flags) + tcp_header[14:20]
            return ip_key + tcp_key + payload, None
        elif proto == 'udp':
            ip_header = packet[14:34]
            udp_header = packet[34:42]
            payload = packet[42:]
            ip_key = ip_header[:8] + b'\x00' * 8
            udp_key = struct.pack('!HHH', 0, 0, 8) + b'\x00\x00'
            return ip_key + udp_key + payload, None
        elif proto == 'icmp':
            ip_header = packet[14:34]
            icmp_header = packet[34:42]
            ip_key = ip_header[:8] + b'\x00' * 8
            icmp_type, code, _, _, _ = struct.unpack('!BBHHH', icmp_header)
            icmp_key = struct.pack('!BBHHH', icmp_type, code, 0, 0, 0)
            return ip_key + icmp_key, None
        elif proto == 'arp':
            arp_header = packet[14:42]
            fields = struct.unpack('!HHBBH6s4s6s4s', arp_header)
            key = struct.pack('!HHBBH6s4s6s4s',
                              fields[0], fields[1], fields[2], fields[3], fields[4],
                              b'\x00'*6, b'\x00'*4, b'\x00'*6, b'\x00'*4)
            return key, None
    except Exception as e:
        logging.warning(f"⚠️ gen_key failed for {proto}: {e}")
    return b'', None

class OsDeceiver:
    def __init__(self, target_host: str, target_os: str, dest=None, nic: str = None):
        self.host = target_host
        self.os = target_os
        self.nic = nic or settings.NIC_PROBE
        self.dest = dest
        self.os_record_path = self.dest or os.path.join(settings.OS_RECORD_PATH, self.os)

        if not os.path.exists(f"/sys/class/net/{self.nic}"):
            raise ValueError(f"NIC '{self.nic}' does not exist.")

        self.conn = TcpConnect(self.host, nic=self.nic)

        os_template = get_os_fingerprint(self.os)
        if not os_template:
            raise ValueError(f"Invalid OS template: {self.os}")

        self.ttl = os_template.get("ttl", 64)
        self.window = os_template.get("window", 8192)
        self.tcp_options = os_template.get("tcp_options", [])
        self.ipid_mode = os_template.get("ipid", "increment")
        self.os_flags = {
            "df": os_template.get("df", False),
            "ecn": os_template.get("ecn", 0),
            "tos": os_template.get("tos", 0)
        }
        self.timestamp_base = {}
        self.ip_id_counter = {}

    def get_timestamp(self, ip):
        now = time.time()
        if ip not in self.timestamp_base:
            self.timestamp_base[ip] = now - random.uniform(1, 10)
        return int((now - self.timestamp_base[ip]) * 1000)

    def get_ip_id(self, ip):
        if self.ipid_mode == "increment":
            self.ip_id_counter[ip] = (self.ip_id_counter.get(ip, 0) + 1) % 65536
            return self.ip_id_counter[ip]
        elif self.ipid_mode == "random":
            return random.randint(0, 65535)
        return 0

    def get_tcp_options(self, src_ip, ts_echo=0):
        opts = []
        for opt in self.tcp_options:
            if opt.startswith("MSS="):
                opts.append(("MSS", int(opt.split("=")[1])))
            elif opt.startswith("WS="):
                opts.append(("WS", int(opt.split("=")[1])))
            elif opt == "TS":
                opts.append(("Timestamp", (self.get_timestamp(src_ip), ts_echo)))
            elif opt == "SACK":
                opts.append(("SAckOK", b""))
            elif opt == "NOP":
                opts.append(("NOP", None))
        return opts

    def send_tcp_rst(self, pkt: Packet):
        try:
            ip = IP(
                src=pkt.l3_field.get("dest_IP_str", pkt.dst_ip),
                dst=pkt.l3_field.get("src_IP_str", pkt.src_ip),
                ttl=self.ttl,
                id=self.get_ip_id(pkt.src_ip),
                tos=self.os_flags.get("tos", 0),
                flags='DF' if self.os_flags.get("df") else 0
            )
            tcp = TCP(
                sport=pkt.l4_field.get("dest_port", 1234),
                dport=pkt.l4_field.get("src_port", 1234),
                flags="R",
                seq=random.randint(0, 4294967295)
            )
            ether = Ether(dst=pkt.eth.src, src=pkt.eth.dst)
            raw = ether / ip / tcp
            self.conn.sock.send(bytes(raw))
            logging.info(f"🚫 Sent TCP RST to {ip.dst}:{tcp.dport}")
        except Exception as e:
            logging.error(f"❌ Failed to send TCP RST: {e}")

    def load_file(self, proto):
        try:
            filename = os.path.join(self.os_record_path, f"{proto}_record.txt")
            if not os.path.exists(filename):
                return {}
            with open(filename, "r") as f:
                raw = json.load(f)
            return {
                base64.b64decode(k): base64.b64decode(v)
                for k, v in raw.items()
            }
        except Exception as e:
            logging.warning(f"⚠️ Failed loading {proto}_record.txt: {e}")
            return {}

    def os_deceive(self, timeout_minutes=5):
        logging.info("🎭 Starting OS deception loop...")
        templates = {p: self.load_file(p) for p in ["tcp", "udp", "icmp", "arp"]}
        end = datetime.now() + timedelta(minutes=timeout_minutes)
        counter = 0

        while datetime.now() < end:
            try:
                raw, addr = self.conn.sock.recvfrom(65565)
                pkt = Packet(raw)
                pkt.interface = self.nic
                pkt.unpack()

                proto = pkt.l4 or pkt.l3
                if not proto:
                    continue

                if proto == 'tcp' and pkt.l4_field.get("dest_port") in settings.FREE_PORT:
                    continue

                if pkt.l3_field.get("dest_IP_str") != self.host:
                    continue

                key, _ = gen_key(proto, pkt.packet)
                template = templates.get(proto, {}).get(key)

                if not template:
                    for k in templates.get(proto, {}):
                        if key.startswith(k[:16]):
                            template = templates[proto][k]
                            break

                if not template:
                    fallback_key = f"default_{proto}_response".encode()
                    template = templates.get(proto, {}).get(fallback_key)

                if template:
                    if proto == 'icmp':
                        time.sleep(random.uniform(0.25, 0.5))
                    resp = synthesize_response(pkt, template, ttl=self.ttl, window=self.window, deceiver=self)
                    if resp:
                        self.conn.sock.send(resp)
                        counter += 1
                        logging.info(f"📤 Sent {proto.upper()} response #{counter}")
                else:
                    if proto == 'tcp':
                        self.send_tcp_rst(pkt)

            except Exception as e:
                logging.error(f"❌ Error in OS deception loop: {e}")

        logging.info(f"🎯 Deception session ended. {counter} responses sent.")
