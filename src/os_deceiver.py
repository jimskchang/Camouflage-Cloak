import os
import json
import base64
import logging
import socket
import struct
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

        # Validate NIC and log MAC
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

    def os_record(self, timeout_minutes: int = 3):
        logging.info("📡 Capturing OS fingerprint packets...")
        timeout = datetime.now() + timedelta(minutes=timeout_minutes)
        tcp, udp, icmp, arp = {}, {}, {}, {}

        while datetime.now() < timeout:
            try:
                packet, _ = self.conn.sock.recvfrom(65565)
                eth_type = struct.unpack("!H", packet[12:14])[0]

                if eth_type == 0x0800:
                    proto = packet[23]
                    if proto == 6:
                        key, _ = gen_tcp_key(packet)
                        tcp[key] = packet
                    elif proto == 1:
                        key, _ = gen_icmp_key(packet)
                        icmp[key] = packet
                    elif proto == 17:
                        key, _ = gen_udp_key(packet)
                        udp[key] = packet
                elif eth_type == 0x0806:
                    key, _ = gen_arp_key(packet)
                    arp[key] = packet
            except Exception as e:
                logging.error(f"❌ Error capturing packet: {e}")

        self.save_record("tcp", tcp)
        self.save_record("udp", udp)
        self.save_record("icmp", icmp)
        self.save_record("arp", arp)
        logging.info("✅ Fingerprint collection complete.")

    def os_deceive(self, timeout_minutes: int = 5):
        logging.info("🌀 Starting OS deception loop...")
        templates = {ptype: self.load_file(ptype) for ptype in ["tcp", "icmp", "udp", "arp"]}
        timeout = datetime.now() + timedelta(minutes=timeout_minutes)
        counter = 0

        while datetime.now() < timeout:
            try:
                raw, _ = self.conn.sock.recvfrom(65565)
                logging.debug(f"📥 Raw packet received: {len(raw)} bytes")

                pkt = Packet(raw)
                pkt.unpack()

                dest_ip = pkt.l3_field.get('dest_IP', b'\x00\x00\x00\x00')
                safe_ip = socket.inet_ntoa(dest_ip) if len(dest_ip) == 4 else "INVALID_IP"
                logging.info(f"Parsed Packet - L3: {pkt.l3}, L4: {pkt.l4}, Dest IP: {safe_ip}")

                proto = pkt.l4 if pkt.l4 else pkt.l3

                if proto == 'tcp' and pkt.l4_field.get('dest_port') in settings.FREE_PORT:
                    continue

                if (pkt.l3 == 'ip' and dest_ip == socket.inet_aton(self.host)) or \
                   (pkt.l3 == 'arp' and pkt.l3_field.get('recv_ip') == socket.inet_aton(self.host)):

                    key, _ = gen_key(proto, pkt.packet)
                    template = templates.get(proto, {}).get(key)

                    if template:
                        response = synthesize_response(pkt, template)
                        if response:
                            self.conn.sock.send(response)
                            counter += 1
                            logging.info(f"📤 Sent {proto.upper()} response #{counter}")
                    elif DEBUG_MODE:
                        with open(UNMATCHED_LOG, "a") as f:
                            f.write(f"[{proto}] {key.hex()}\n")
            except Exception as e:
                logging.error(f"❌ Error in deception loop: {e}")


# --- Response Synthesis ---
def synthesize_response(req_pkt: Packet, raw_template: bytes) -> bytes:
    try:
        rsp = Packet(raw_template)
        rsp.unpack()

        rsp.l2_field['dMAC'] = req_pkt.l2_field['sMAC']
        rsp.l2_field['sMAC'] = req_pkt.l2_field['dMAC']

        if req_pkt.l3 == 'ip':
            rsp.l3_field['src_IP'] = req_pkt.l3_field['dest_IP']
            rsp.l3_field['dest_IP'] = req_pkt.l3_field['src_IP']

        if req_pkt.l3 == 'tcp':
            rsp.l4_field['src_port'] = req_pkt.l4_field['dest_port']
            rsp.l4_field['dest_port'] = req_pkt.l4_field['src_port']
            rsp.l4_field['seq'] = req_pkt.l4_field['ack_num']
            rsp.l4_field['ack_num'] = req_pkt.l4_field['seq'] + 1
            if 8 in rsp.l4_field.get('kind_seq', []):
                rsp.l4_field['option_field']['ts_echo_reply'] = req_pkt.l4_field['option_field']['ts_val']

        elif req_pkt.l3 == 'icmp':
            rsp.l4_field['ID'] = req_pkt.l4_field['ID']
            rsp.l4_field['seq'] = req_pkt.l4_field['seq']

        elif req_pkt.l3 == 'udp':
            rsp.l4_field['ID'] = 0
            rsp.l4_field['seq'] = 0

        elif req_pkt.l3 == 'arp':
            rsp.l3_field['sender_mac'] = settings.MAC.encode()
            rsp.l3_field['sender_ip'] = socket.inet_aton(settings.HOST)
            rsp.l3_field['recv_mac'] = req_pkt.l3_field['sender_mac']
            rsp.l3_field['recv_ip'] = req_pkt.l3_field['sender_ip']

        rsp.pack()
        return rsp.packet
    except Exception as e:
        logging.error(f"❌ Synthesis error: {e}")
        return b''


# --- Key Normalization Helpers ---
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
