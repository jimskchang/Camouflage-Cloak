import os
import logging
import socket
import struct
from src.settings import ETH_HEADER_LEN, IP_HEADER_LEN, ARP_HEADER_LEN, ICMP_HEADER_LEN
from src.Packet import Packet
from src.tcp import TcpConnect

class OsDeceiver:
    def __init__(self, host, target_os):
        self.host = host
        self.target_os = target_os
        self.conn = TcpConnect(host)
        self.os_record_path = f"os_record/{self.target_os}"
        self.create_os_folder()

    def create_os_folder(self):
        """ Ensure OS-specific record directory exists """
        if not os.path.exists(self.os_record_path):
            logging.info(f"Creating OS record folder: {self.os_record_path}")
            os.makedirs(self.os_record_path)

    def os_record(self):
        """ Captures and logs OS fingerprinting packets (ARP, ICMP) """
        logging.info(f"[OS Fingerprint Capture] Capturing fingerprint packets for {self.host}")

        arp_pkt_dict = {}
        icmp_pkt_dict = {}

        arp_record_file = os.path.join(self.os_record_path, "arp_record.txt")
        icmp_record_file = os.path.join(self.os_record_path, "icmp_record.txt")

        while True:
            packet, _ = self.conn.sock.recvfrom(65565)
            eth_header = packet[:ETH_HEADER_LEN]
            eth = struct.unpack("!6s6sH", eth_header)
            eth_protocol = socket.ntohs(eth[2])

            if eth_protocol == 8:  # IP packets
                ip_header = packet[ETH_HEADER_LEN:ETH_HEADER_LEN + IP_HEADER_LEN]
                _, _, _, _, _, _, PROTOCOL, _, src_IP, dest_IP = struct.unpack('!BBHHHBBH4s4s', ip_header)

                if PROTOCOL == 1:  # ICMP
                    logging.info("[Fingerprint Capture] Processing ICMP packet...")
                    icmp_header = packet[ETH_HEADER_LEN + IP_HEADER_LEN: ETH_HEADER_LEN + IP_HEADER_LEN + ICMP_HEADER_LEN]
                    icmp_type, code, checksum, ID, seq = struct.unpack('BbHHh', icmp_header)

                    if socket.inet_ntoa(dest_IP) == self.host:
                        key, packet_val = gen_icmp_key(packet)
                        icmp_pkt_dict[key] = packet

                        with open(icmp_record_file, 'w') as f:
                            f.write(str(icmp_pkt_dict))
                            f.flush()
                            logging.info("[Fingerprint Capture] ICMP fingerprint stored.")

            elif eth_protocol == 1544:  # ARP
                logging.info("[Fingerprint Capture] Processing ARP packet...")
                arp_header = packet[ETH_HEADER_LEN: ETH_HEADER_LEN + ARP_HEADER_LEN]
                hw_type, proto_type, hw_size, proto_size, opcode, sender_mac, sender_ip, recv_mac, recv_ip = struct.unpack(
                    '!2s2s1s1s2s6s4s6s4s', arp_header)

                if socket.inet_ntoa(recv_ip) == self.host:
                    key, packet_val = gen_arp_key(packet)
                    arp_pkt_dict[key] = packet

                    with open(arp_record_file, 'w') as f:
                        f.write(str(arp_pkt_dict))
                        f.flush()
                        logging.info("[Fingerprint Capture] ARP fingerprint stored.")

    def os_deceive(self):
        """ Performs OS deception by modifying fingerprinting responses """
        logging.info(f"[OS Deception] Intercepting OS fingerprinting packets for {self.host}...")
        logging.info(f"[OS Deception] Sending deceptive Windows 10 response...")
