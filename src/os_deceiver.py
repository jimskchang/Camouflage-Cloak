import os
import json
import base64
import logging
import socket
import struct
from datetime import datetime, timedelta
from typing import Dict, Any

import src.settings as settings
from src.Packet import Packet
from src.tcp import TcpConnect

DEBUG_MODE = os.environ.get("DEBUG", "0") == "1"
UNMATCHED_LOG = os.path.join(settings.OS_RECORD_DIR, "unmatched_keys.log")

class OsDeceiver:
    def __init__(self, target_host: str, target_os: str, dest=None):
        self.host = target_host
        self.os = target_os
        self.conn = TcpConnect(target_host)
        self.dest = dest
        self.os_record_path = self.dest or os.path.join(settings.OS_RECORD_DIR, self.os)

        os.makedirs(self.os_record_path, exist_ok=True)
        logging.info(f"OS Deception ready for {self.os} using path: {self.os_record_path}")

    def save_record(self, pkt_type: str, record: Dict[bytes, bytes]):
        file_path = os.path.join(self.os_record_path, f"{pkt_type}_record.txt")
        with open(file_path, "w") as f:
            encoded = {
                base64.b64encode(k).decode(): base64.b64encode(v).decode()
                for k, v in record.items() if v
            }
            json.dump(encoded, f, indent=2)
        logging.info(f"Saved {pkt_type} record to {file_path}")

    def load_file(self, pkt_type: str) -> Dict[bytes, bytes]:
        file_path = os.path.join(self.os_record_path, f"{pkt_type}_record.txt")
        try:
            with open(file_path, "r") as f:
                raw = json.load(f)
                return {
                    base64.b64decode(k): base64.b64decode(v)
                    for k, v in raw.items()
                }
        except Exception as e:
            logging.error(f"Failed to load {file_path}: {e}")
            return {}

    def os_record(self, timeout_minutes: int = 3):
        logging.info("Starting OS fingerprint collection...")
        timeout = datetime.now() + timedelta(minutes=timeout_minutes)

        tcp, udp, icmp, arp = {}, {}, {}, {}

        while datetime.now() < timeout:
            try:
                packet, _ = self.conn.sock.recvfrom(65565)
                eth_type = struct.unpack("!H", packet[12:14])[0]

                if eth_type == 0x0800:  # IPv4
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
                logging.error(f"Error capturing packet: {e}")

        self.save_record("tcp", tcp)
        self.save_record("udp", udp)
        self.save_record("icmp", icmp)
        self.save_record("arp", arp)
        logging.info("Fingerprint collection complete.")

    def os_deceive(self, timeout_minutes: int = 5):
        templates = {
            'tcp': self.load_file('tcp'),
            'icmp': self.load_file('icmp'),
            'udp': self.load_file('udp'),
            'arp': self.load_file('arp')
        }
        timeout = datetime.now() + timedelta(minutes=timeout_minutes)
        counter = 0

        while datetime.now() < timeout:
            try:
                raw, _ = self.conn.sock.recvfrom(65565)
                pkt = Packet(raw)
                pkt.unpack()
                proto = pkt.get_proc()

                if proto == 'tcp' and pkt.l4_field['dest_port'] in settings.FREE_PORT:
                    continue

                if (pkt.l3 == 'ip' and pkt.l3_field['dest_IP'] == socket.inet_aton(self.host)) or \
                   (pkt.l3 == 'arp' and pkt.l3_field['recv_ip'] == socket.inet_aton(self.host)):

                    key, _ = gen_key(proto, pkt.packet)
                    template = templates.get(proto, {}).get(key)

                    if template:
                        response = synthesize_response(pkt, template)
                        if response:
                            self.conn.sock.send(response)
                            counter += 1
                            logging.info(f"Sent {proto} response #{counter}")
                    elif DEBUG_MODE:
                        with open(UNMATCHED_LOG, "a") as f:
                            f.write(f"[{proto}] {key.hex()}\n")
            except Exception as e:
                logging.error(f"Error in deception loop: {e}")

# --- Synthesis & Key Helpers ---
def synthesize_response(req_pkt: Packet, raw_template: bytes) -> bytes:
    try:
        rsp = Packet(raw_template)
        rsp.unpack()

        # Swap fields
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
            rsp.l3_field['sender_mac'] = settings.mac
            rsp.l3_field['sender_ip'] = socket.inet_aton(settings.host)
            rsp.l3_field['recv_mac'] = req_pkt.l3_field['sender_mac']
            rsp.l3_field['recv_ip'] = req_pkt.l3_field['sender_ip']

        rsp.pack()
        return rsp.packet
    except Exception as e:
        logging.error(f"Synthesis error: {e}")
        return b''

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

# Include your original gen_tcp_key, gen_icmp_key, gen_udp_key, gen_arp_key functions here...
# For brevity, they're omitted from this snippet unless you want them re-pasted.
