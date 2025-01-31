from datetime import datetime
import logging
import socket
import struct
import os

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
        self.os_type = os_type.lower()  # Normalize OS name
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

    def save_packet_records(self, records):
        """Saves recorded packets to a predefined folder."""
        record_dir = os.path.join(settings.RECORDS_FOLDER, self.os_type)
        os.makedirs(record_dir, exist_ok=True)

        for pkt_type, record in records.items():
            if record:
                try:
                    filename = os.path.join(record_dir, f"{pkt_type}_record.json")
                    with open(filename, "w") as f:
                        f.write(str(record))
                    logging.info(f"Saved {pkt_type} records to {filename}.")
                except Exception as e:
                    logging.error(f"Failed to save {pkt_type} records: {e}")

    def gen_tcp_key(self, packet):
        """Generates a TCP key for identification."""
        tcp_header = packet[settings.ETH_HEADER_LEN + settings.IP_HEADER_LEN:
                            settings.ETH_HEADER_LEN + settings.IP_HEADER_LEN + settings.TCP_HEADER_LEN]
        src_port, dest_port = struct.unpack("!HH", tcp_header[:4])
        return f"{src_port}-{dest_port}", packet

    def gen_icmp_key(self, packet):
        """Generates an ICMP key for identification."""
        icmp_header = packet[settings.ETH_HEADER_LEN + settings.IP_HEADER_LEN:
                             settings.ETH_HEADER_LEN + settings.IP_HEADER_LEN + 4]
        icmp_type, code = struct.unpack("!BB", icmp_header[:2])
        return f"{icmp_type}-{code}", packet

    def gen_udp_key(self, packet):
        """Generates a UDP key for identification."""
        udp_header = packet[settings.ETH_HEADER_LEN + settings.IP_HEADER_LEN:
                            settings.ETH_HEADER_LEN + settings.IP_HEADER_LEN + 8]
        src_port, dest_port = struct.unpack("!HH", udp_header[:4])
        return f"{src_port}-{dest_port}", packet

    def gen_arp_key(self, packet):
        """Generates an ARP key for identification."""
        arp_header = packet[settings.ETH_HEADER_LEN:settings.ETH_HEADER_LEN + settings.ARP_HEADER_LEN]
        sender_ip, target_ip = struct.unpack("!4s4s", arp_header[14:22])
        return f"{socket.inet_ntoa(sender_ip)}-{socket.inet_ntoa(target_ip)}", packet

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
            try:
                raw_pkt, _ = self.conn.sock.recvfrom(65565)
                pkt = Packet(packet=raw_pkt)
                pkt.unpack()
                proc = pkt.get_proc()

                # OS Deception Logic
                if (pkt.l3 == "ip" and pkt.l3_field["dest_IP"] == socket.inet_aton(self.host)) or (
                    pkt.l3 == "arp" and pkt.l3_field["recv_ip"] == socket.inet_aton(self.host)
                ):
                    rsp = self.deceived_pkt_synthesis(proc, pkt, template_dict)
                    if rsp:
                        self.conn.sock.send(rsp)

            except Exception as e:
                logging.error(f"Error during OS deception: {e}")

    def load_file(self, pkt_type):
        """Loads the OS deception template file."""
        record_dir = os.path.join(settings.RECORDS_FOLDER, self.os_type)
        filename = os.path.join(record_dir, f"{pkt_type}_record.json")

        if not os.path.exists(filename):
            logging.warning(f"Template file {filename} not found.")
            return None

        try:
            with open(filename, "r") as f:
                return f.read()
        except Exception as e:
            logging.error(f"Failed to load {filename}: {e}")
            return None

    def deceived_pkt_synthesis(self, proc, pkt, template_dict):
        """Synthesizes a deceived packet based on recorded templates."""
        if proc in template_dict and template_dict[proc]:
            logging.info(f"Using deception template for {proc}")
            return template_dict[proc]
        return None
