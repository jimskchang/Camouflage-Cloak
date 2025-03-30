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
from src.fingerprint_utils import gen_key

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

        mac_path = f"/sys/class/net/{self.nic}/address"
        try:
            with open(mac_path, "r") as f:
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
            "ecn": os_template.get("ecn", 0)
        }

        self.ip_id_counter = 0
        self.ip_state = {}
        self.timestamp_base = {}

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

    def send_tcp_rst(self, pkt: Packet):
        try:
            ip = IP(
                src=pkt.l3_field.get("dest_IP_str", socket.inet_ntoa(pkt.l3_field.get("src_IP", b"\x00\x00\x00\x00"))),
                dst=pkt.l3_field.get("src_IP_str", socket.inet_ntoa(pkt.l3_field.get("dest_IP", b"\x00\x00\x00\x00"))),
                ttl=self.ttl,
                id=self.get_ip_id(),
                tos=self.os_flags.get("tos", 0)
            )
            if self.os_flags.get("df"):
                ip.flags = "DF"

            tcp = TCP(
                sport=pkt.l4_field.get("dest_port", 1234),
                dport=pkt.l4_field.get("src_port", 1234),
                flags="R",
                seq=random.randint(0, 4294967295)
            )
            ether = Ether(dst=pkt.l2_field.get("sMAC", b""), src=pkt.l2_field.get("dMAC", b""))
            raw = ether / ip / tcp
            self.conn.sock.send(bytes(raw))
            logging.info(f"🚫 Sent TCP RST to {ip.dst}:{tcp.dport}")
        except Exception as e:
            logging.error(f"❌ Failed to send TCP RST: {e}")

    def os_deceive(self, timeout_minutes: int = 5):
        from src.fingerprint_utils import gen_key
        from src.response import synthesize_response

        logging.info("🌀 Starting OS deception loop...")
        templates = {ptype: self.load_file(ptype) for ptype in ["tcp", "icmp", "udp", "arp"]}
        timeout = datetime.now() + timedelta(minutes=timeout_minutes)
        counter = 0

        while datetime.now() < timeout:
            try:
                raw, addr = self.conn.sock.recvfrom(65565)
                ip_str = addr[0]
                logging.debug(f"📥 Raw packet received: {len(raw)} bytes")

                pkt = Packet(raw)
                pkt.interface = self.nic
                pkt.unpack()

                dest_ip = pkt.l3_field.get('dest_IP', b'\x00\x00\x00\x00')
                safe_ip = socket.inet_ntoa(dest_ip) if len(dest_ip) == 4 else "INVALID_IP"
                logging.info(f"Parsed Packet - L3: {pkt.l3}, L4: {pkt.l4}, Dest IP: {safe_ip}")

                proto = pkt.l4 if pkt.l4 else pkt.l3
                self.track_ip_state(ip_str, proto)

                if proto == 'tcp' and pkt.l4_field.get('dest_port') in settings.FREE_PORT:
                    continue

                if (pkt.l3 == 'ip' and dest_ip == socket.inet_aton(self.host)) or \
                   (pkt.l3 == 'arp' and pkt.l3_field.get('recv_ip') == socket.inet_aton(self.host)):

                    key, _ = gen_key(proto, pkt.packet)
                    template = templates.get(proto, {}).get(key)

                    if not template:
                        logging.warning(f"⚠️ No exact template match for {proto} key (len={len(key)}). Trying fuzzy match...")
                        for k in templates.get(proto, {}):
                            if key.startswith(k[:16]):
                                template = templates[proto][k]
                                logging.info(f"🔍 Fuzzy match hit for {proto.upper()} template (prefix match)!")
                                break

                    if not template:
                        default_key = f"default_{proto}_response".encode()
                        template = templates.get(proto, {}).get(default_key)
                        if template:
                            logging.info(f"✨ Using default_{proto}_response fallback template")

                    if template:
                        if proto == 'icmp':
                            time.sleep(random.uniform(0.25, 0.5))
                        response = synthesize_response(pkt, template, ttl=self.ttl, window=self.window, deceiver=self)
                        if response:
                            self.conn.sock.send(response)
                            counter += 1
                            logging.info(f"📤 Sent {proto.upper()} response #{counter}")
                        continue

                    # Fallback behavior: no template found at all
                    if proto == 'udp':
                        self.send_icmp_port_unreachable(pkt)
                    elif proto == 'tcp':
                        self.send_tcp_rst(pkt)

                    if settings.AUTO_LEARN_MISSING:
                        logging.info(f"🧠 Learning new {proto.upper()} template on the fly")
                        templates[proto][key] = pkt.packet
                        self.save_record(proto, templates[proto])
                    elif DEBUG_MODE:
                        with open(UNMATCHED_LOG, "a") as f:
                            f.write(f"[{proto}] {key.hex()}\n")

            except Exception as e:
                logging.error(f"❌ Error in deception loop: {e}")

    def track_ip_state(self, ip: str, proto: str):
        self.ip_state[ip] = self.ip_state.get(ip, 0) + 1

    def load_file(self, proto: str):
        filename = os.path.join(self.os_record_path, f"{proto}_record.txt")
        try:
            with open(filename, "r") as f:
                raw = json.load(f)
            return {base64.b64decode(k): base64.b64decode(v) for k, v in raw.items()}
        except Exception as e:
            logging.error(f"❌ Failed to load template {filename}: {e}")
            return {}

    def save_record(self, proto: str, data: dict):
        filename = os.path.join(self.os_record_path, f"{proto}_record.txt")
        try:
            encoded = {base64.b64encode(k).decode(): base64.b64encode(v).decode() for k, v in data.items()}
            with open(filename, "w") as f:
                json.dump(encoded, f, indent=2)
        except Exception as e:
            logging.error(f"❌ Failed to save {proto} template: {e}")

    def send_icmp_port_unreachable(self, pkt: Packet):
        try:
            original_ip = pkt.packet[14:34]
            original_udp = pkt.packet[34:42]
            data = original_ip + original_udp

            ip = IP(
                src=pkt.l3_field.get("dest_IP_str", socket.inet_ntoa(pkt.l3_field.get("src_IP", b"\x00\x00\x00\x00"))),
                dst=pkt.l3_field.get("src_IP_str", socket.inet_ntoa(pkt.l3_field.get("dest_IP", b"\x00\x00\x00\x00"))),
                ttl=self.ttl,
                id=self.get_ip_id(),
                tos=self.os_flags.get("tos", 0)
            )
            if self.os_flags.get("df"):
                ip.flags = "DF"

            icmp = ICMP(type=3, code=3)
            ether = Ether(dst=pkt.l2_field.get("sMAC", b""), src=pkt.l2_field.get("dMAC", b""))
            raw = ether / ip / icmp / data
            self.conn.sock.send(bytes(raw))
            logging.info(f"🚫 Sent ICMP Port Unreachable to {ip.dst}")
        except Exception as e:
            logging.error(f"❌ Failed to send ICMP Port Unreachable: {e}")

    def export_state_log(self):
        state_log = os.path.join(self.os_record_path, "ip_state_log.txt")
        try:
            with open(state_log, "w") as f:
                for ip, count in self.ip_state.items():
                    f.write(f"{ip}: {count}\n")
            logging.info(f"📊 Exported IP state log to {state_log}")
        except Exception as e:
            logging.error(f"❌ Failed to export IP state log: {e}")
