# --- Final Corrected os_deceiver.py ---

import os
import json
import base64
import logging
import socket
import struct
from datetime import datetime, timedelta
from typing import Dict

import src.settings as settings
from src.Packet import Packet
from src.tcp import TcpConnect

DEBUG_MODE = os.environ.get("DEBUG", "0") == "1"
UNMATCHED_LOG = os.path.join(settings.OS_RECORD_PATH, "unmatched_keys.log")

class OsDeceiver:
    def __init__(self, target_host: str, target_os: str, dest=None):
        self.host = target_host
        self.os = target_os
        self.conn = TcpConnect(target_host)
        self.dest = dest
        self.os_record_path = self.dest or os.path.join(settings.OS_RECORD_PATH, self.os)

        os.makedirs(self.os_record_path, exist_ok=True)
        logging.info(f"OS Deception ready for {self.os} using path: {self.os_record_path}")

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
            logging.error(f"\u274c Fail to load {file_path}: {e}")
            return {}

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

                proto = pkt.l4 if pkt.l4 else pkt.l3

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
                            logging.info(f"\ud83d\udce4 Sent {proto} response #{counter}")
                    elif DEBUG_MODE:
                        with open(UNMATCHED_LOG, "a") as f:
                            f.write(f"[{proto}] {key.hex()}\n")
            except Exception as e:
                logging.error(f"\u274c Error in deception loop: {e}")

# --- Synthesize spoofed response from template ---
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
        elif req_pkt.l3 == 'icmp':
            rsp.l4_field['ID'] = req_pkt.l4_field['ID']
            rsp.l4_field['seq'] = req_pkt.l4_field['seq']
        elif req_pkt.l3 == 'arp':
            rsp.l3_field['sender_mac'] = settings.MAC.encode()
            rsp.l3_field['sender_ip'] = socket.inet_aton(settings.HOST)
            rsp.l3_field['recv_mac'] = req_pkt.l3_field['sender_mac']
            rsp.l3_field['recv_ip'] = req_pkt.l3_field['sender_ip']

        rsp.pack()
        return rsp.packet
    except Exception as e:
        logging.error(f"\u274c Synthesis error: {e}")
        return b''

# --- Key Helpers ---
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
    ip_header = packet[14:34]
    tcp_header = packet[34:54]
    src_port, dest_port, seq, ack_num, offset_flags = struct.unpack('!HHLLH', tcp_header[:14])
    offset = (offset_flags >> 12) * 4
    payload = packet[54:54+offset-20]
    ip_key = ip_header[:8] + b'\x00' * 8
    tcp_key = struct.pack('!HHLLH', 0, dest_port, 0, 0, offset_flags) + tcp_header[14:20]
    return ip_key + tcp_key + payload, None

def gen_udp_key(packet: bytes):
    ip_header = packet[14:34]
    udp_header = packet[34:42]
    payload = packet[42:]
    ip_key = ip_header[:8] + b'\x00' * 8
    udp_key = struct.pack('!HHH', 0, 0, 8) + b'\x00\x00'
    return ip_key + udp_key + payload, None

def gen_icmp_key(packet: bytes):
    ip_header = packet[14:34]
    icmp_header = packet[34:42]
    ip_key = ip_header[:8] + b'\x00' * 8
    icmp_type, code, checksum, icmp_id, seq = struct.unpack('!BBHHH', icmp_header)
    icmp_key = struct.pack('!BBHHH', icmp_type, code, 0, 0, 0)
    return ip_key + icmp_key, None

def gen_arp_key(packet: bytes):
    arp_header = packet[14:42]
    fields = struct.unpack('!HHBBH6s4s6s4s', arp_header)
    key = struct.pack('!HHBBH6s4s6s4s', fields[0], fields[1], fields[2], fields[3], fields[4],
                      b'\x00'*6, b'\x00'*4, b'\x00'*6, b'\x00'*4)
    return key, None
