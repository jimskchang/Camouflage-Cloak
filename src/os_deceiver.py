import logging
import socket
import struct
import os
from _datetime import datetime, timedelta
from typing import Any

# Delay import to avoid circular dependency
import src.settings as settings
from src.Packet import Packet
from src.tcp import TcpConnect  # ✅ Ensure we import TcpConnect for connection handling

class OsDeceiver:
    def __init__(self, target_host, camouflage_host, target_os):
        """
        target_host: The IP address being mimicked (Target)
        camouflage_host: The real host running the deception (Camouflage Cloak)
        target_os: The OS fingerprint we are trying to mimic
        """
        self.target_host = target_host
        self.camouflage_host = camouflage_host
        self.target_os = target_os

        # ✅ Create a raw socket connection for packet reception
        self.conn = TcpConnect(self.camouflage_host)

        self.knocking_history = {}
        self.white_list = {}
        self.port_seq = [4441, 5551, 6661]

        # ✅ Ensure OS-specific record directory exists
        self.os_record_path = f"os_record/{self.target_os}"
        if not os.path.exists(self.os_record_path):
            logging.info(f"Creating OS record folder: {self.os_record_path}")
            os.makedirs(self.os_record_path)

    def os_record(self):
        """ Captures and logs OS fingerprinting packets (ARP, ICMP) """
        logging.info(f"Intercepting OS fingerprinting packets for {self.target_host}")

        icmp_pkt_dict = {}
        arp_pkt_dict = {}

        icmp_record_file = os.path.join(self.os_record_path, "icmp_record.txt")
        arp_record_file = os.path.join(self.os_record_path, "arp_record.txt")

        while True:
            packet, _ = self.conn.sock.recvfrom(65565)
            eth_header = packet[: settings.ETH_HEADER_LEN]
            eth_protocol = socket.ntohs(struct.unpack("!6s6sH", eth_header)[2])

            if eth_protocol == 8:  # IP packets
                ip_header = packet[settings.ETH_HEADER_LEN: settings.ETH_HEADER_LEN + settings.IP_HEADER_LEN]
                _, _, _, _, _, _, PROTOCOL, _, src_IP, dest_IP = struct.unpack("!BBHHHBBH4s4s", ip_header)

                if PROTOCOL == 1 and socket.inet_ntoa(dest_IP) == self.target_host:  # ICMP
                    key, packet_val = self.gen_icmp_key(packet)
                    icmp_pkt_dict[key] = packet
                    with open(icmp_record_file, "w") as f:
                        f.write(str(icmp_pkt_dict))
                        f.flush()
                    logging.info(f"ICMP Packet Captured from {socket.inet_ntoa(src_IP)}")

            elif eth_protocol == 1544:  # ARP packets
                arp_header = packet[settings.ETH_HEADER_LEN: settings.ETH_HEADER_LEN + settings.ARP_HEADER_LEN]
                _, _, _, _, _, sender_mac, sender_ip, recv_mac, recv_ip = struct.unpack("!2s2s1s1s2s6s4s6s4s", arp_header)

                if socket.inet_ntoa(recv_ip) == self.target_host:
                    key, packet_val = self.gen_arp_key(packet)
                    arp_pkt_dict[key] = packet
                    with open(arp_record_file, "w") as f:
                        f.write(str(arp_pkt_dict))
                        f.flush()
                    logging.info(f"ARP Packet Captured from {socket.inet_ntoa(sender_ip)}")

    def os_deceive(self):
        """ Performs OS deception by modifying fingerprinting responses """
        logging.info(f"Executing OS deception for {self.target_host}, mimicking {self.target_os}")

        template_dict = {
            "arp": self.load_file("arp"),
            "tcp": self.load_file("tcp"),
            "udp": self.load_file("udp"),
            "icmp": self.load_file("icmp"),
        }

        while True:
            raw_pkt, _ = self.conn.sock.recvfrom(65565)
            pkt = Packet(packet=raw_pkt)
            pkt.unpack()
            proc = pkt.get_proc()

            if (pkt.l3 == "ip" and pkt.l3_field["dest_IP"] == socket.inet_aton(self.target_host)) or \
               (pkt.l3 == "arp" and pkt.l3_field["recv_ip"] == socket.inet_aton(self.target_host)):
                req = pkt
                rsp = self.deceived_pkt_synthesis(proc, req, template_dict)

                if rsp:
                    logging.info(f"Sending deceptive {proc.upper()} response to {self.target_host}")
                    self.conn.sock.send(rsp)

    def load_file(self, pkt_type: str):
        """ Loads stored OS fingerprinting response records """
        file_path = os.path.join(self.os_record_path, f"{pkt_type}_record.txt")

        if not os.path.exists(file_path):
            logging.warning(f"Missing {pkt_type} fingerprint record.")
            return {}

        with open(file_path, "r") as file:
            try:
                return eval(file.readline())  # Safely read the dictionary
            except Exception as e:
                logging.error(f"Error loading {pkt_type} record: {e}")
                return {}
