from datetime import datetime
import logging
import socket
import struct
from typing import Dict

import src.settings as settings
from src.Packet import Packet
from src.tcp import TcpConnect

# Constants for Protocols
ETH_TYPE_IP = 0x0800
ETH_TYPE_ARP = 0x0806
PROTO_TCP = 6
PROTO_UDP = 17
PROTO_ICMP = 1

logging.basicConfig(level=logging.INFO)


class OsDeceiver:
    def __init__(self, host, os_type):
        self.host = host
        self.os_type = os_type
        self.conn = TcpConnect(host)

    def os_record(self):
        """Records OS-specific responses for TCP, ICMP, UDP, and ARP."""
        packet_records = {"tcp": {}, "icmp": {}, "udp": {}, "arp": {}}

        while True:
            try:
                packet, _ = self.conn.sock.recvfrom(65565)
                eth_protocol, src_ip, dest_ip, protocol = self.extract_headers(packet)

                if eth_protocol == ETH_TYPE_IP:
                    if protocol == PROTO_TCP:
                        self.record_tcp_packet(packet, packet_records["tcp"], src_ip, dest_ip)
                    elif protocol == PROTO_ICMP:
                        self.record_icmp_packet(packet, packet_records["icmp"], src_ip, dest_ip)
                    elif protocol == PROTO_UDP:
                        self.record_udp_packet(packet, packet_records["udp"], src_ip, dest_ip)
                elif eth_protocol == ETH_TYPE_ARP:
                    self.record_arp_packet(packet, packet_records["arp"], src_ip, dest_ip)

                # Save the records periodically
                self.save_packet_records(packet_records)

            except Exception as e:
                logging.error(f"Error recording packet: {e}")

    def extract_headers(self, packet):
        """Extracts Ethernet and IP headers."""
        eth_header = packet[:settings.ETH_HEADER_LEN]
        eth = struct.unpack("!6s6sH", eth_header)
        eth_protocol = socket.ntohs(eth[2])

        if eth_protocol == ETH_TYPE_IP:
            ip_header = packet[settings.ETH_HEADER_LEN:settings.ETH_HEADER_LEN + settings.IP_HEADER_LEN]
            _, _, _, _, _, _, protocol, _, src_ip, dest_ip = struct.unpack("!BBHHHBBH4s4s", ip_header)
            return eth_protocol, src_ip, dest_ip, protocol

        return eth_protocol, None, None, None

    def record_tcp_packet(self, packet, tcp_dict, src_ip, dest_ip):
        """Records TCP packets."""
        if dest_ip == socket.inet_aton(self.host):  # Incoming request
            key, packet_val = self.gen_tcp_key(packet)
            if key not in tcp_dict:
                tcp_dict[key] = None

        elif src_ip == socket.inet_aton(self.host):  # Response packet
            for key in tcp_dict.keys():
                if tcp_dict[key] is None:
                    logging.info(f"Adding TCP response for key: {key}")
                    tcp_dict[key] = packet
                    break

    def record_icmp_packet(self, packet, icmp_dict, src_ip, dest_ip):
        """Records ICMP packets."""
        if dest_ip == socket.inet_aton(self.host):
            key, _ = self.gen_icmp_key(packet)
            if key not in icmp_dict:
                icmp_dict[key] = None

        elif src_ip == socket.inet_aton(self.host):
            for key in icmp_dict.keys():
                if icmp_dict[key] is None:
                    logging.info(f"Adding ICMP response for key: {key}")
                    icmp_dict[key] = packet
                    break

    def record_udp_packet(self, packet, udp_dict, src_ip, dest_ip):
        """Records UDP packets."""
        if dest_ip == socket.inet_aton(self.host):
            key, _ = self.gen_udp_key(packet)
            if key not in udp_dict:
                udp_dict[key] = None

    def record_arp_packet(self, packet, arp_dict, src_ip, dest_ip):
        """Records ARP packets."""
        if src_ip and dest_ip == socket.inet_aton(self.host):
            key, _ = self.gen_arp_key(packet)
            if key not in arp_dict:
                arp_dict[key] = None

    def save_packet_records(self, records):
        """Saves recorded packets to files periodically."""
        for pkt_type, record in records.items():
            if record:
                with open(f"{pkt_type}_record.txt", "w") as f:
                    f.write(str(record))
                logging.info(f"Saved {pkt_type} records.")

    def os_deceive(self):
        """Deceives OS fingerprinting attempts."""
        logging.info(f"Loading OS deception template for {self.os_type}")
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

            # OS Deception
            if (pkt.l3 == "ip" and pkt.l3_field["dest_IP"] == socket.inet_aton(self.host)) or (
                pkt.l3 == "arp" and pkt.l3_field["recv_ip"] == socket.inet_aton(self.host)
            ):
                rsp = self.deceived_pkt_synthesis(proc, pkt, template_dict)
                if rsp:
                    self.conn.sock.send(rsp)
