from datetime import datetime, timedelta
import logging
import random
import socket
import struct
import os

import src.settings as settings
from src.Packet import Packet
from src.tcp import TcpConnect


class OsDeceiver:
    white_list = []

    def __init__(self, host, os):
        self.host = host
        self.os = os
        self.conn = TcpConnect(host)
        self.knocking_history = {}
        self.white_list = {}
        self.port_seq = [4441, 5551, 6661]

    def os_record(self, output_path=None):
        """Records OS-specific network responses for deception"""
        if not output_path:
            output_path = os.path.join(settings.TS_OS_OUTPUT_DIR, f"{self.os}_record.txt")
        
        logging.info(f"📄 Recording OS packets to {output_path}")

        pkt_dict = {}
        port_pair_seq = []
        key_seq = []

        while True:
            packet, _ = self.conn.sock.recvfrom(65565)
            eth_header = packet[: settings.ETH_HEADER_LEN]
            eth = struct.unpack('!6s6sH', eth_header)
            eth_protocol = socket.ntohs(eth[2])

            # IP Packet
            if eth_protocol == 8:
                ip_header = packet[settings.ETH_HEADER_LEN: settings.ETH_HEADER_LEN + settings.IP_HEADER_LEN]
                _, _, _, _, _, _, PROTOCOL, _, src_IP, dest_IP = struct.unpack('!BBHHHBBH4s4s', ip_header)

                # TCP Packet
                if PROTOCOL == 6:
                    tcp_header = packet[settings.ETH_HEADER_LEN + settings.IP_HEADER_LEN:
                                        settings.ETH_HEADER_LEN + settings.IP_HEADER_LEN + settings.TCP_HEADER_LEN]
                    src_port, dest_port, _, _, _, flags, _, _, _ = struct.unpack('!HHLLBBHHH', tcp_header)

                    # Store incoming packet
                    if dest_IP == socket.inet_aton(self.host):
                        key, packet_val = gen_tcp_key(packet)
                        if packet_val['flags'] == 4:
                            continue
                        port_pair_seq.append((src_port, dest_port))
                        key_seq.append(key)
                        if key not in pkt_dict:
                            pkt_dict[key] = None

                    # Store response packet
                    elif src_IP == socket.inet_aton(self.host) and (dest_port, src_port) in port_pair_seq:
                        pkt_index = port_pair_seq.index((dest_port, src_port))
                        key = key_seq[pkt_index]
                        if pkt_dict[key] is None:
                            logging.info(f"Adding response packet to record.")
                            pkt_dict[key] = packet

                    # Save to file
                    with open(output_path, 'w') as f:
                        f.write(str(pkt_dict))

    def store_rsp(self, output_path=None):
        """Stores response packets"""
        if not output_path:
            output_path = os.path.join(settings.TS_OS_OUTPUT_DIR, "rsp_record.txt")

        logging.info(f"📄 Storing responses to {output_path}")

        rsp = {}
        while True:
            packet, _ = self.conn.sock.recvfrom(65565)
            eth_header = packet[: settings.ETH_HEADER_LEN]
            eth = struct.unpack('!6s6sH', eth_header)
            eth_protocol = socket.ntohs(eth[2])

            if eth_protocol == 8:
                ip_header = packet[settings.ETH_HEADER_LEN: settings.ETH_HEADER_LEN + settings.IP_HEADER_LEN]
                _, _, _, _, _, _, PROTOCOL, _, src_IP, dest_IP = struct.unpack('!BBHHHBBH4s4s', ip_header)

                # TCP Packet
                if PROTOCOL == 6 and src_IP == socket.inet_aton(self.host):
                    pkt = Packet(packet)
                    src_port = pkt.l4_field['src_port']
                    if src_port not in rsp:
                        rsp[src_port] = []
                    rsp[src_port].append(packet)

                    with open(output_path, 'w') as f:
                        f.write(str(rsp))

    def os_deceive(self, output_path=None):
        """Performs OS deception"""
        if not output_path:
            output_path = os.path.join(settings.TS_OS_OUTPUT_DIR, f"{self.os}_deception_log.txt")

        logging.info(f"⚠️ Starting OS deception for {self.os}")

        dec_count = 0
        template_dict = {
            'arp': self.load_file('arp'),
            'tcp': self.load_file('tcp'),
            'udp': self.load_file('udp'),
            'icmp': self.load_file('icmp')
        }
        logging.info(f"✅ {self.os} template loaded.")

        while True:
            raw_pkt, _ = self.conn.sock.recvfrom(65565)
            pkt = Packet(packet=raw_pkt)
            pkt.unpack()
            proc = pkt.get_proc()

            """OS Deception"""
            if (pkt.l3 == 'ip' and pkt.l3_field['dest_IP'] == socket.inet_aton(settings.TARGET_HOST)) or \
                    (pkt.l3 == 'arp' and pkt.l3_field['recv_ip'] == socket.inet_aton(settings.TARGET_HOST)):

                req = pkt
                rsp = deceived_pkt_synthesis(proc, req, template_dict)
                if rsp:
                    dec_count += 1
                    logging.info(f"Sending deceptive packet {dec_count} for {proc}")
                    self.conn.sock.send(rsp)

    def load_file(self, pkt_type: str):
        """Loads stored OS record files"""
        output_path = os.path.join(settings.TS_OS_OUTPUT_DIR, f"{self.os}_{pkt_type}_record.txt")
        logging.info(f"📂 Loading {output_path}")

        try:
            with open(output_path, 'r') as file:
                packet_dict = eval(file.readline())
                return {k: v for (k, v) in packet_dict.items() if v is not None}
        except FileNotFoundError:
            logging.error(f"File {output_path} not found.")
            return {}

# Ensure functions exist
def gen_tcp_key(packet):
    return packet[:20], {}

def deceived_pkt_synthesis(proc, req, template):
    return None
