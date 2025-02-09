from _datetime import datetime, timedelta
import logging
import random
import socket
import struct
import os  # Ensure os module is correctly imported
from typing import List, Any

import src.settings as settings
from src.Packet import Packet
from src.tcp import TcpConnect


class OsDeceiver:
    white_list = []

    def __init__(self, host, target_os):  # ✅ Use `target_os` instead of `os`
        self.host = host
        self.target_os = target_os  # ✅ Store correctly
        self.conn = TcpConnect(host)
        self.knocking_history = {}
        self.white_list = {}
        self.port_seq = [4441, 5551, 6661]

        # Ensure OS-specific record directory exists
        self.os_record_path = f"os_record/{self.target_os}"  # ✅ Use `target_os`
        if not os.path.exists(self.os_record_path):
            logging.info(f"Creating OS record folder: {self.os_record_path}")
            os.makedirs(self.os_record_path)

    def os_record(self):
        """ Captures and logs OS fingerprinting packets (ARP, ICMP) """
        arp_pkt_dict = {}
        icmp_pkt_dict = {}

        arp_record_file = os.path.join(self.os_record_path, "arp_record.txt")
        icmp_record_file = os.path.join(self.os_record_path, "icmp_record.txt")

        logging.info(f"Intercepting OS fingerprinting packets for {self.host}")

        while True:
            packet, _ = self.conn.sock.recvfrom(65565)
            eth_header = packet[: settings.ETH_HEADER_LEN]
            eth = struct.unpack('!6s6sH', eth_header)
            eth_protocol = socket.ntohs(eth[2])

            if eth_protocol == 8:  # IP packets
                ip_header = packet[settings.ETH_HEADER_LEN: settings.ETH_HEADER_LEN + settings.IP_HEADER_LEN]
                _, _, _, _, _, _, PROTOCOL, _, src_IP, dest_IP = struct.unpack('!BBHHHBBH4s4s', ip_header)

                logging.info(f"Received IP packet - Protocol: {PROTOCOL}, Source: {socket.inet_ntoa(src_IP)}, Dest: {socket.inet_ntoa(dest_IP)}")

                if PROTOCOL == 1:  # ICMP packets
                    icmp_header = packet[settings.ETH_HEADER_LEN + settings.IP_HEADER_LEN:
                                         settings.ETH_HEADER_LEN + settings.IP_HEADER_LEN + settings.ICMP_HEADER_LEN]
                    icmp_type, code, checksum, ID, seq = struct.unpack('BbHHh', icmp_header)

                    if socket.inet_ntoa(dest_IP) == self.host:
                        key, packet_val = gen_icmp_key(packet)
                        icmp_pkt_dict[key] = packet

                        logging.info(f"ICMP Record Updated - Count: {len(icmp_pkt_dict)}")
                        with open(icmp_record_file, 'w') as f:
                            f.write(str(icmp_pkt_dict))
                            f.flush()

            elif eth_protocol == 1544:  # ARP packets
                arp_header = packet[settings.ETH_HEADER_LEN: settings.ETH_HEADER_LEN + settings.ARP_HEADER_LEN]
                hw_type, proto_type, hw_size, proto_size, opcode, sender_mac, sender_ip, recv_mac, recv_ip = struct.unpack(
                    '2s2s1s1s2s6s4s6s4s', arp_header)

                if socket.inet_ntoa(recv_ip) == self.host:
                    key, packet_val = gen_arp_key(packet)
                    arp_pkt_dict[key] = packet

                    logging.info(f"ARP Record Updated - Count: {len(arp_pkt_dict)}")
                    with open(arp_record_file, 'w') as f:
                        f.write(str(arp_pkt_dict))
                        f.flush()

    def os_deceive(self):
        """ Performs OS deception by modifying fingerprinting responses """
        logging.info(f"Executing OS deception for {self.host}, mimicking {self.target_os}")
        logging.info(f"Sending deceptive Windows 10 response...")

        # Load fingerprinting response templates
        template_dict = {
            'arp': self.load_file("arp"),
            'tcp': self.load_file("tcp"),
            'udp': self.load_file("udp"),
            'icmp': self.load_file("icmp")
        }

        while True:
            raw_pkt, _ = self.conn.sock.recvfrom(65565)
            pkt = Packet(packet=raw_pkt)
            pkt.unpack()
            proc = pkt.get_proc()

            # OS deception logic
            if (pkt.l3 == 'ip' and pkt.l3_field['dest_IP'] == socket.inet_aton(self.host)) or \
               (pkt.l3 == 'arp' and pkt.l3_field['recv_ip'] == socket.inet_aton(self.host)):
                req = pkt
                rsp = self.deceived_pkt_synthesis(proc, req, template_dict)

                if rsp:
                    logging.info(f"Sent deceptive {proc.upper()} packet.")
                    self.conn.sock.send(rsp)

    def load_file(self, pkt_type: str):
        """ Loads OS fingerprinting response records """
        file_path = os.path.join(self.os_record_path, f"{pkt_type}_record.txt")

        if not os.path.exists(file_path):
            logging.warning(f"Missing {pkt_type} fingerprint record. Skipping...")
            return {}

        with open(file_path, 'r') as file:
            try:
                return eval(file.readline())  # Safely evaluate the stored dictionary
            except Exception as e:
                logging.error(f"Error loading {pkt_type} record: {e}")
                return {}
