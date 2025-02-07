import logging
import random
import socket
import struct
import os
import sys
from datetime import datetime

# Ensure correct module path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# Import settings and dependencies
try:
    import settings
except ImportError:
    logging.warning("Failed to import settings.py. Using default values.")
    settings = None

from Packet import Packet
from tcp import TcpConnect


class OsDeceiver:
    def __init__(self, host, os_name):
        self.host = host
        self.os = os_name
        self.conn = TcpConnect(host)
        self.knocking_history = {}
        self.white_list = {}
        self.port_seq = [4441, 5551, 6661]  # Hardcoded port knocking sequence

    def os_record(self, output_path=None):
        """Records incoming OS fingerprinting packets and saves them."""
        if output_path is None:
            output_path = settings.TARGET_OS_OUTPUT_DIR

        os.makedirs(output_path, exist_ok=True)
        record_file = os.path.join(output_path, f"{self.os}_record.txt")

        pkt_dict = {}
        port_pair_seq = []
        key_seq = []

        logging.info(f"Recording OS fingerprints to: {record_file}")

        while True:
            packet, _ = self.conn.sock.recvfrom(65565)
            eth_header = packet[:settings.ETH_HEADER_LEN]
            eth = struct.unpack('!6s6sH', eth_header)
            eth_protocol = socket.ntohs(eth[2])

            if eth_protocol == 8:  # IP packets
                ip_header = packet[settings.ETH_HEADER_LEN: settings.ETH_HEADER_LEN + settings.IP_HEADER_LEN]
                _, _, _, _, _, _, PROTOCOL, _, src_IP, dest_IP = struct.unpack('!BBHHHBBH4s4s', ip_header)

                if PROTOCOL == 6:  # TCP
                    tcp_header = packet[settings.ETH_HEADER_LEN + settings.IP_HEADER_LEN:
                                        settings.ETH_HEADER_LEN + settings.IP_HEADER_LEN + settings.TCP_HEADER_LEN]
                    src_port, dest_port, seq, ack_num, offset, flags, window, checksum, urgent_ptr = struct.unpack(
                        '!HHLLBBHHH', tcp_header)

                    if dest_IP == socket.inet_aton(self.host):
                        key, packet_val = self.gen_tcp_key(packet)
                        if key not in pkt_dict:
                            pkt_dict[key] = None
                        port_pair_seq.append((src_port, dest_port))
                        key_seq.append(key)

                    elif src_IP == socket.inet_aton(self.host) and (dest_port, src_port) in port_pair_seq:
                        pkt_index = port_pair_seq.index((dest_port, src_port))
                        key = key_seq[pkt_index]
                        if pkt_dict[key] is None:
                            logging.info("Captured OS fingerprinting response packet.")
                            pkt_dict[key] = packet

                    # Save to file
                    with open(record_file, 'w') as f:
                        f.write(str(pkt_dict))

    def store_rsp(self, output_path=None):
        """Stores response packets for OS deception."""
        if output_path is None:
            output_path = settings.TARGET_OS_OUTPUT_DIR

        os.makedirs(output_path, exist_ok=True)
        rsp_record_file = os.path.join(output_path, f"{self.os}_rsp_record.txt")

        rsp = {}

        logging.info(f"Storing response packets at: {rsp_record_file}")

        while True:
            packet, _ = self.conn.sock.recvfrom(65565)
            eth_header = packet[:settings.ETH_HEADER_LEN]
            eth = struct.unpack('!6s6sH', eth_header)
            eth_protocol = socket.ntohs(eth[2])

            if eth_protocol == 8:  # IP packets
                ip_header = packet[settings.ETH_HEADER_LEN: settings.ETH_HEADER_LEN + settings.IP_HEADER_LEN]
                _, _, _, _, _, _, PROTOCOL, _, src_IP, dest_IP = struct.unpack('!BBHHHBBH4s4s', ip_header)

                if PROTOCOL == 6 and src_IP == socket.inet_aton(self.host):
                    pkt = Packet(packet)
                    pkt.unpack()
                    src_port = pkt.l4_field['src_port']
                    if src_port not in rsp:
                        rsp[src_port] = []
                    rsp[src_port].append(packet)

                    # Save to file
                    with open(rsp_record_file, 'w') as f:
                        f.write(str(rsp))

    def os_deceive(self, output_path=None):
        """Deceives OS fingerprinting scans."""
        if output_path is None:
            output_path = settings.TARGET_OS_OUTPUT_DIR

        os.makedirs(output_path, exist_ok=True)

        logging.info(f"Loading OS deception templates from: {output_path}")

        template_dict = {
            'arp': self.load_file('arp', output_path),
            'tcp': self.load_file('tcp', output_path),
            'udp': self.load_file('udp', output_path),
            'icmp': self.load_file('icmp', output_path)
        }

        while True:
            raw_pkt, _ = self.conn.sock.recvfrom(65565)
            pkt = Packet(packet=raw_pkt)
            pkt.unpack()
            proc = pkt.get_proc()

            if proc == 'tcp' and pkt.l3_field['dest_IP'] == socket.inet_aton(self.host):
                if pkt.l4_field['dest_port'] in settings.FREE_PORT:
                    continue  # Ignore free ports

                self.add_knocking_history(pkt)
                if self.verify_knocking(pkt):
                    self.white_list[pkt.l3_field['src_IP']] = datetime.now()
                    logging.info(f"Added {pkt.l3_field['src_IP']} to whitelist.")

                if pkt.l3_field['src_IP'] in self.white_list:
                    if self.white_list[pkt.l3_field['src_IP']] + settings.white_list_validation >= datetime.now():
                        continue
                    else:
                        self.white_list.pop(pkt.l3_field['src_IP'])

            if (pkt.l3 == 'ip' and pkt.l3_field['dest_IP'] == socket.inet_aton(self.host)) or \
                    (pkt.l3 == 'arp' and pkt.l3_field['recv_ip'] == socket.inet_aton(self.host)):
                req = pkt
                rsp = self.deceived_pkt_synthesis(proc, req, template_dict)
                if rsp:
                    self.conn.sock.send(rsp)

    def load_file(self, pkt_type, output_path):
        """Loads stored OS fingerprinting templates."""
        record_file = os.path.join(output_path, f"{self.os}_{pkt_type}_record.txt")

        if not os.path.exists(record_file):
            logging.warning(f"Missing OS deception template: {record_file}")
            return {}

        with open(record_file, 'r') as f:
            packet_dict = eval(f.readline())

        return {k: v for k, v in packet_dict.items() if v is not None}

    def add_knocking_history(self, packet):
        """Records port knocking history."""
        self.knocking_history.setdefault(packet.l3_field['src_IP'], []).append(packet.l4_field['dest_port'])

    def verify_knocking(self, packet):
        """Verifies if a valid port knocking sequence was received."""
        try:
            idx = [self.knocking_history[packet.l3_field['src_IP']].index(port) for port in self.port_seq]
            return all(idx[i + 1] - idx[i] == 1 for i in range(len(idx) - 1))
        except ValueError:
            return False
