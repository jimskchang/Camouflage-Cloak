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


class OsDeceiver:
    def __init__(self, target_host: str, target_os: str):
        self.host = target_host
        self.os = target_os
        self.conn = TcpConnect(target_host)

        self.os_record_path = os.path.join(settings.OS_RECORD_DIR, self.os)
        if not os.path.isdir(self.os_record_path):
            logging.error(f"❌ OS record path not found: {self.os_record_path}")
        else:
            logging.info(f"📌 OS Deception initialized for {self.os} using {self.os_record_path}")

    def load_file(self, pkt_type: str) -> Dict[bytes, bytes]:
        """
        Loads pre-recorded packet templates from JSON (base64-encoded keys/values).
        """
        file_path = os.path.join(self.os_record_path, f"{pkt_type}_record.txt")

        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = f.read().strip()
                if not data:
                    logging.warning(f"⚠ {file_path} is empty.")
                    return {}
                raw_dict = json.loads(data)
                return {
                    base64.b64decode(k): base64.b64decode(v)
                    for k, v in raw_dict.items() if v
                }
        except Exception as e:
            logging.error(f"❌ Failed to load {file_path}: {e}")
            return {}

    def os_deceive(self, timeout_minutes: int = 5):
        """
        Main deception loop — reads packets and responds with spoofed replies.
        """
        template_dict = {
            'tcp': self.load_file('tcp'),
            'icmp': self.load_file('icmp'),
            'udp': self.load_file('udp'),
            'arp': self.load_file('arp')
        }
        logging.info(f"📦 Loaded templates for {self.os}")

        timeout = datetime.now() + timedelta(minutes=timeout_minutes)
        dec_count = 0

        while datetime.now() < timeout:
            try:
                raw_pkt, _ = self.conn.sock.recvfrom(65565)
                pkt = Packet(packet=raw_pkt)
                pkt.unpack()

                if (pkt.l3 == 'ip' and pkt.l3_field.get('dest_IP') == socket.inet_aton(self.host)) or \
                   (pkt.l3 == 'arp' and pkt.l3_field.get('recv_ip') == socket.inet_aton(self.host)):

                    key, _ = gen_key(pkt.l3, pkt.packet)
                    template_bytes = template_dict.get(pkt.l3, {}).get(key)

                    if template_bytes:
                        response = synthesize_response(pkt, template_bytes)
                        if response:
                            self.conn.sock.send(response)
                            dec_count += 1
                            logging.info(f"📤 Sent {pkt.l3} response ({dec_count})")
                    else:
                        logging.debug(f"🔍 No template match for incoming {pkt.l3} packet.")
            except Exception as e:
                logging.error(f"❌ Error in deception loop: {e}")

        logging.info("🛑 OS Deception session ended.")


def synthesize_response(req_pkt: Packet, raw_template: bytes) -> bytes:
    """
    Adjusts raw template packet to respond to the incoming request appropriately.
    """
    try:
        rsp = Packet(packet=raw_template)
        rsp.unpack()

        if req_pkt.l3 == 'tcp':
            rsp.l2_field['dMAC'] = req_pkt.l2_field['sMAC']
            rsp.l2_field['sMAC'] = req_pkt.l2_field['dMAC']
            rsp.l3_field['src_IP'] = req_pkt.l3_field['dest_IP']
            rsp.l3_field['dest_IP'] = req_pkt.l3_field['src_IP']
            rsp.l4_field['src_port'] = req_pkt.l4_field['dest_port']
            rsp.l4_field['dest_port'] = req_pkt.l4_field['src_port']
            rsp.l4_field['seq'] = req_pkt.l4_field['ack_num']
            rsp.l4_field['ack_num'] = req_pkt.l4_field['seq'] + 1
            if 8 in rsp.l4_field.get('kind_seq', []):
                rsp.l4_field['option_field']['ts_echo_reply'] = req_pkt.l4_field['option_field']['ts_val']

        elif req_pkt.l3 == 'icmp':
            rsp.l2_field['dMAC'] = req_pkt.l2_field['sMAC']
            rsp.l2_field['sMAC'] = req_pkt.l2_field['dMAC']
            rsp.l3_field['src_IP'] = req_pkt.l3_field['dest_IP']
            rsp.l3_field['dest_IP'] = req_pkt.l3_field['src_IP']
            rsp.l4_field['ID'] = req_pkt.l4_field['ID']
            rsp.l4_field['seq'] = req_pkt.l4_field['seq']

        elif req_pkt.l3 == 'udp':
            rsp.l2_field['dMAC'] = req_pkt.l2_field['sMAC']
            rsp.l2_field['sMAC'] = req_pkt.l2_field['dMAC']
            rsp.l3_field['src_IP'] = req_pkt.l3_field['dest_IP']
            rsp.l3_field['dest_IP'] = req_pkt.l3_field['src_IP']
            rsp.l4_field['ID'] = 0
            rsp.l4_field['seq'] = 0

        elif req_pkt.l3 == 'arp':
            rsp.l2_field['dMAC'] = req_pkt.l2_field['sMAC']
            rsp.l2_field['sMAC'] = settings.mac
            rsp.l3_field['sender_mac'] = settings.mac
            rsp.l3_field['sender_ip'] = socket.inet_aton(settings.host)
            rsp.l3_field['recv_mac'] = req_pkt.l3_field['sender_mac']
            rsp.l3_field['recv_ip'] = req_pkt.l3_field['sender_ip']

        rsp.pack()
        return rsp.packet
    except Exception as e:
        logging.error(f"❌ Failed to synthesize response: {e}")
        return b''


def gen_key(proto: str, packet: bytes):
    """
    Wrapper to generate normalized packet keys for matching.
    """
    if proto == 'tcp':
        return gen_tcp_key(packet)
    elif proto == 'icmp':
        return gen_icmp_key(packet)
    elif proto == 'udp':
        return gen_udp_key(packet)
    elif proto == 'arp':
        return gen_arp_key(packet)
    return b'', None


# Use the original gen_*_key functions here (not shown for brevity)
# They normalize packets and strip non-essential fields to create a matchable key.
# You can reuse: gen_tcp_key(), gen_icmp_key(), gen_udp_key(), gen_arp_key()
# Make sure those are included in your project and imported as needed.
