from datetime import datetime
import logging
import socket
import struct
import os
import json
import base64

import src.settings as settings
from src.Packet import Packet
from src.tcp import TcpConnect
from src.utils import (
    convert_bytes_to_ip,
    convert_ip_to_bytes,
    calculate_checksum
)


class OsDeceiver:
    def __init__(self, host, os_type):
        self.host = host
        self.os_type = os_type
        self.conn = TcpConnect(host)
        self.template_dict = {
            'arp': self.load_file('arp'),
            'tcp': self.load_file('tcp'),
            'udp': self.load_file('udp'),
            'icmp': self.load_file('icmp')
        }

    def os_record(self, output_path=None):
        """Records OS-specific network responses for deception."""
        if not output_path:
            output_path = os.path.join(settings.TS_OS_OUTPUT_DIR, f"{self.os_type}_record.json")

        logging.info(f"Recording OS packets to {output_path}")

        pkt_dict = {}

        while True:
            packet, _ = self.conn.sock.recvfrom(65565)
            pkt = Packet(packet)
            pkt.unpack()

            if pkt.l3_field['dest_IP'] == self.host:
                key, packet_val = self.gen_tcp_key(pkt)

                if packet_val['flags'] == 4:  # Ignore RST packets
                    continue

                if key not in pkt_dict:
                    pkt_dict[key] = {
                        "l3_field": pkt.l3_field,
                        "l4_field": pkt.l4_field,
                        "data": base64.b64encode(pkt.packet).decode()
                    }

                # Save to file
                with open(output_path, 'w') as f:
                    json.dump(pkt_dict, f, indent=4)

    def store_rsp(self, output_path=None):
        """Stores response packets."""
        if not output_path:
            output_path = os.path.join(settings.TS_OS_OUTPUT_DIR, "rsp_record.json")

        logging.info(f"Storing responses to {output_path}")

        rsp = {}

        while True:
            packet, _ = self.conn.sock.recvfrom(65565)
            pkt = Packet(packet)
            pkt.unpack()

            if pkt.l3_field['src_IP'] == self.host:
                src_port = pkt.l4_field.get('src_port', 0)

                if src_port not in rsp:
                    rsp[src_port] = []

                rsp[src_port].append({
                    "l3_field": pkt.l3_field,
                    "l4_field": pkt.l4_field,
                    "data": base64.b64encode(pkt.packet).decode()
                })

                with open(output_path, 'w') as f:
                    json.dump(rsp, f, indent=4)

    def os_deceive(self, output_path=None):
        """Performs OS deception."""
        if not output_path:
            output_path = os.path.join(settings.TS_OS_OUTPUT_DIR, f"{self.os_type}_deception_log.json")

        logging.info(f"Starting OS deception for {self.os_type}")

        dec_count = 0

        while True:
            raw_pkt, _ = self.conn.sock.recvfrom(65565)
            pkt = Packet(packet=raw_pkt)
            pkt.unpack()
            proc = pkt.get_proc()

            if (pkt.l3 == 'ip' and pkt.l3_field['dest_IP'] == settings.TARGET_HOST) or \
                    (pkt.l3 == 'arp' and pkt.l3_field.get('recv_ip') == settings.TARGET_HOST):

                req = pkt
                rsp = self.deceived_pkt_synthesis(proc, req)
                if rsp:
                    dec_count += 1
                    logging.info(f"Sending deceptive packet {dec_count} for {proc}")
                    self.conn.sock.send(rsp)

    def load_file(self, pkt_type: str):
        """Loads stored OS record files."""
        output_path = os.path.join(settings.TS_OS_OUTPUT_DIR, f"{self.os_type}_{pkt_type}_record.json")
        logging.info(f"Loading {output_path}")

        try:
            with open(output_path, 'r') as file:
                return json.load(file)
        except FileNotFoundError:
            logging.error(f"File {output_path} not found.")
            return {}
        except json.JSONDecodeError:
            logging.error(f"Error parsing {output_path}, file might be corrupted.")
            return {}

    @staticmethod
    def gen_tcp_key(pkt: Packet):
        """Generate a unique key for TCP packets."""
        src_IP = pkt.l3_field['src_IP']
        dest_IP = pkt.l3_field['dest_IP']
        src_port = pkt.l4_field.get('src_port', 0)
        dest_port = pkt.l4_field.get('dest_port', 0)
        flags = pkt.l4_field.get('flags', 0)

        key = f"{src_IP}-{dest_IP}-{src_port}-{dest_port}-{flags}"
        return key, {'flags': flags}

    def deceived_pkt_synthesis(self, proc, req):
        """Generates a deceptive packet based on template data."""
        key, _ = self.gen_tcp_key(req)

        if proc in self.template_dict and key in self.template_dict[proc]:
            raw_template = self.template_dict[proc][key]
            template_pkt = Packet(raw_template)
            template_pkt.unpack()

            # Modify fields to create a deceptive response
            template_pkt.l3_field['src_IP'] = req.l3_field['dest_IP']
            template_pkt.l3_field['dest_IP'] = req.l3_field['src_IP']
            template_pkt.l4_field['src_port'] = req.l4_field['dest_port']
            template_pkt.l4_field['dest_port'] = req.l4_field['src_port']
            template_pkt.l4_field['seq'] = req.l4_field['ack_num']
            template_pkt.l4_field['ack_num'] = req.l4_field['seq'] + 1

            # Pack and send the response
            template_pkt.pack()
            return template_pkt.packet

        logging.warning(f"No template found for {proc} key={key}.")
        return None
