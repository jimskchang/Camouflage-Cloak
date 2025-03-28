import os
import json
import base64
import logging
import socket
import struct
import time
from datetime import datetime, timedelta
from typing import Dict

import src.settings as settings
from src.settings import OS_TEMPLATES
from src.Packet import Packet
from src.tcp import TcpConnect

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

        os_template = OS_TEMPLATES.get(self.os.lower())
        if not os_template:
            logging.error(f"❌ OS template '{self.os}' not found in settings.OS_TEMPLATES.")
            raise ValueError(f"Invalid OS template: {self.os}")

        self.ttl = os_template.get("ttl")
        self.window = os_template.get("window")
        self.ip_state = {}  # Track probe counts per IP

        logging.info(f"🎭 TTL and Window Spoofing -> TTL={self.ttl}, Window={self.window}")
        logging.info(f"🛡️ OS Deception initialized for '{self.os}' via NIC '{self.nic}'")
        logging.info(f"📁 Using OS template path: {self.os_record_path}")

    def save_record(self, pkt_type: str, record: Dict[bytes, bytes]):
        file_path = os.path.join(self.os_record_path, f"{pkt_type}_record.txt")
        try:
            encoded = {
                base64.b64encode(k).decode(): base64.b64encode(v).decode()
                for k, v in record.items() if v
            }
            with open(file_path, "w") as f:
                json.dump(encoded, f, indent=2)
            logging.info(f"✅ Saved {pkt_type} record to {file_path}")
        except Exception as e:
            logging.error(f"❌ Failed to save {pkt_type} record: {e}")

    def load_file(self, pkt_type: str) -> Dict[bytes, bytes]:
        file_path = os.path.join(self.os_record_path, f"{pkt_type}_record.txt")
        try:
            with open(file_path, "r") as f:
                raw = json.load(f)
            parsed = {}
            for k, v in raw.items():
                try:
                    parsed[base64.b64decode(k)] = base64.b64decode(v)
                except Exception as decode_error:
                    logging.warning(f"⚠️ Skipping malformed entry in {pkt_type}: {decode_error}")
            logging.info(f"📦 Loaded {len(parsed)} entries from {file_path}")
            return parsed
        except Exception as e:
            logging.error(f"❌ Fail to load {file_path}: {e}")
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

                    if template:
                        if proto == 'icmp':
                            time.sleep(random.uniform(0.25, 0.5))  # ICMP latency injection

                        response = synthesize_response(pkt, template, ttl=self.ttl, window=self.window)
                        if response:
                            self.conn.sock.send(response)
                            counter += 1
                            logging.info(f"📤 Sent {proto.upper()} response #{counter}")
                    elif DEBUG_MODE:
                        with open(UNMATCHED_LOG, "a") as f:
                            f.write(f"[{proto}] {key.hex()}\n")
            except Exception as e:
                logging.error(f"❌ Error in deception loop: {e}")

        self.export_state_log()

    def track_ip_state(self, ip: str, proto: str):
        if ip not in self.ip_state:
            self.ip_state[ip] = {
                'first_seen': time.time(),
                'tcp_count': 0,
                'icmp_count': 0,
                'udp_count': 0,
                'arp_count': 0
            }
        key = f"{proto}_count"
        if key in self.ip_state[ip]:
            self.ip_state[ip][key] += 1

    def export_state_log(self):
        try:
            state_path = os.path.join(self.os_record_path, "state_log.json")
            with open(state_path, "w") as f:
                json.dump(self.ip_state, f, indent=2)
            logging.info(f"🧾 Exported per-IP state log to {state_path}")
        except Exception as e:
            logging.error(f"❌ Failed to export state log: {e}")
