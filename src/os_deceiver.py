import os
import logging
import socket
import struct
from datetime import datetime
from src import settings
from src.Packet import Packet
from src.tcp import TcpConnect


class OsDeceiver:
    """Handles OS fingerprint capture and deception"""

    def __init__(self, host, os_name):
        self.host = host
        self.os = os_name.lower().replace(" ", "_")  # Normalize OS name, e.g., "win 10" -> "win_10"
        self.conn = TcpConnect(host)
        self.record_path = f"os_record/{self.os}"  # OS-specific directory for storing packets
        os.makedirs(self.record_path, exist_ok=True)  # Ensure directory exists

    def os_record(self):
        """Captures packets from the target and stores logs in OS-specific files"""
        pkt_dict = {"tcp": {}, "icmp": {}, "udp": {}, "arp": {}}
        logging.info(f"Starting packet capture for OS: {self.os} ({self.host})")

        while True:
            try:
                # Receive raw packet
                packet, _ = self.conn.sock.recvfrom(65565)
                eth_protocol, _, dest_IP, PROTOCOL = self._parse_ethernet_ip(packet)

                # Process based on protocol
                if eth_protocol == 8:  # IP packets
                    if PROTOCOL == 6:  # TCP
                        key, _ = self._generate_tcp_key(packet)
                        pkt_dict["tcp"][key] = packet
                    elif PROTOCOL == 1:  # ICMP
                        key, _ = self._generate_icmp_key(packet)
                        pkt_dict["icmp"][key] = packet
                    elif PROTOCOL == 17:  # UDP
                        key, _ = self._generate_udp_key(packet)
                        pkt_dict["udp"][key] = packet
                elif eth_protocol == 1544:  # ARP
                    key, _ = self._generate_arp_key(packet)
                    pkt_dict["arp"][key] = packet

                # Save packets to files
                self._write_record("tcp", pkt_dict["tcp"])
                self._write_record("icmp", pkt_dict["icmp"])
                self._write_record("udp", pkt_dict["udp"])
                self._write_record("arp", pkt_dict["arp"])

            except socket.error as e:
                logging.error(f"Socket error while receiving packets: {e}")
            except Exception as e:
                logging.error(f"Unexpected error in os_record: {e}")

    def _write_record(self, pkt_type: str, data: dict):
        """Writes captured packets to OS-specific files"""
        file_path = f"{self.record_path}/{pkt_type}_record.txt"
        try:
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(str(data))
            logging.info(f"Saved {pkt_type} records for {self.os} in {file_path}")
        except IOError as e:
            logging.error(f"Error writing to {file_path}: {e}")

    def _parse_ethernet_ip(self, packet):
        """Parses Ethernet and IP headers"""
        eth_header = packet[:settings.ETH_HEADER_LEN]
        eth = struct.unpack("!6s6sH", eth_header)
        eth_protocol = socket.ntohs(eth[2])

        ip_header = packet[settings.ETH_HEADER_LEN: settings.ETH_HEADER_LEN + settings.IP_HEADER_LEN]
        _, _, _, _, _, _, PROTOCOL, _, _, dest_IP = struct.unpack("!BBHHHBBH4s4s", ip_header)

        return eth_protocol, _, dest_IP, PROTOCOL

    def _generate_tcp_key(self, packet: bytes):
        """Generates a unique key for TCP packet"""
        ip_header = packet[settings.ETH_HEADER_LEN: settings.ETH_HEADER_LEN + settings.IP_HEADER_LEN]
        tcp_header = packet[settings.ETH_HEADER_LEN + settings.IP_HEADER_LEN: settings.ETH_HEADER_LEN +
                            settings.IP_HEADER_LEN + settings.TCP_HEADER_LEN]

        src_IP, dest_IP = struct.unpack("!4s4s", ip_header[12:20])
        src_port, dest_port, _, _, _, flags, _, _, _ = struct.unpack("!HHLLBBHHH", tcp_header)

        key = f"{socket.inet_ntoa(src_IP)}:{src_port} -> {socket.inet_ntoa(dest_IP)}:{dest_port} (Flags: {flags})"
        return key, packet

    def _generate_icmp_key(self, packet: bytes):
        """Generates a unique key for ICMP packet"""
        ip_header = packet[settings.ETH_HEADER_LEN: settings.ETH_HEADER_LEN + settings.IP_HEADER_LEN]
        icmp_header = packet[settings.ETH_HEADER_LEN + settings.IP_HEADER_LEN: settings.ETH_HEADER_LEN +
                            settings.IP_HEADER_LEN + settings.ICMP_HEADER_LEN]

        src_IP, dest_IP = struct.unpack("!4s4s", ip_header[12:20])
        icmp_type, _, _, ID, seq = struct.unpack("BbHHh", icmp_header)

        key = f"{socket.inet_ntoa(src_IP)} -> {socket.inet_ntoa(dest_IP)} (ICMP Type: {icmp_type}, ID: {ID}, Seq: {seq})"
        return key, packet

    def _generate_udp_key(self, packet: bytes):
        """Generates a unique key for UDP packet"""
        ip_header = packet[settings.ETH_HEADER_LEN: settings.ETH_HEADER_LEN + settings.IP_HEADER_LEN]
        udp_header = packet[settings.ETH_HEADER_LEN + settings.IP_HEADER_LEN: settings.ETH_HEADER_LEN +
                            settings.IP_HEADER_LEN + settings.UDP_HEADER_LEN]

        src_IP, dest_IP = struct.unpack("!4s4s", ip_header[12:20])
        src_port, dest_port, _, _ = struct.unpack("!4H", udp_header)

        key = f"{socket.inet_ntoa(src_IP)}:{src_port} -> {socket.inet_ntoa(dest_IP)}:{dest_port} (UDP)"
        return key, packet

    def _generate_arp_key(self, packet: bytes):
        """Generates a unique key for ARP packet"""
        arp_header = packet[settings.ETH_HEADER_LEN: settings.ETH_HEADER_LEN + settings.ARP_HEADER_LEN]
        sender_mac, sender_ip, recv_mac, recv_ip = struct.unpack("!6s4s6s4s", arp_header[8:28])

        key = f"ARP {socket.inet_ntoa(sender_ip)} -> {socket.inet_ntoa(recv_ip)}"
        return key, packet
