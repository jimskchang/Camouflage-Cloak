import logging
import socket
import struct
from datetime import datetime
from typing import Dict

from src import settings
from src.Packet import Packet
from src.tcp import TcpConnect

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s]: %(message)s")


class OsDeceiver:
    """ Handles OS deception and response recording. """

    def __init__(self, host: str, os_name: str):
        self.host = host
        self.os = os_name
        self.conn = TcpConnect(host)
        self.knocking_history: Dict[bytes, list] = {}
        self.white_list: Dict[bytes, datetime] = {}
        self.port_seq = [4441, 5551, 6661]  # Predefined port knocking sequence

    def os_record(self):
        """ Records OS response packets for deception. """
        pkt_dict = {}
        key_seq = []
        port_pair_seq = []
        count = 1

        while True:
            try:
                packet, _ = self.conn.sock.recvfrom(65565)
            except socket.error as e:
                logging.error(f"Socket error while receiving packet: {e}")
                continue

            eth_protocol, src_IP, dest_IP, PROTOCOL = self._parse_ethernet_ip(packet)

            if eth_protocol == 8 and PROTOCOL == 6:  # TCP Packet
                src_port, dest_port, flags = self._parse_tcp(packet)
                if dest_IP == socket.inet_aton(self.host):  # Incoming request
                    key, _ = gen_tcp_key(packet)
                    if flags == 4:  # Ignore RST packets
                        continue
                    port_pair_seq.append((src_port, dest_port))
                    key_seq.append(key)
                    pkt_dict.setdefault(key, None)
                elif src_IP == socket.inet_aton(self.host) and (dest_port, src_port) in port_pair_seq:
                    pkt_index = port_pair_seq.index((dest_port, src_port))
                    key = key_seq[pkt_index]
                    if pkt_dict[key] is None:
                        logging.info(f"Adding TCP reply {count}")
                        count += 1
                        pkt_dict[key] = packet

                self._write_record('tcp_record.txt', pkt_dict)

    def store_rsp(self):
        """ Stores response packets for later deception. """
        rsp = {}

        while True:
            try:
                packet, _ = self.conn.sock.recvfrom(65565)
            except socket.error as e:
                logging.error(f"Socket error while receiving response packet: {e}")
                continue

            eth_protocol, src_IP, dest_IP, PROTOCOL = self._parse_ethernet_ip(packet)

            if eth_protocol == 8 and PROTOCOL == 6 and src_IP == socket.inet_aton(self.host):  # TCP response
                pkt = Packet(packet)
                pkt.unpack()
                src_port = pkt.l4_field.get("src_port")

                if src_port not in rsp:
                    rsp[src_port] = []
                rsp[src_port].append(packet)

                self._write_record('rsp_record.txt', rsp)

    def load_file(self, pkt_type: str):
        """ Loads stored OS response templates. """
        file_path = f"os_record/{self.os}/{pkt_type}_record.txt"

        try:
            with open(file_path, "r", encoding="utf-8") as f:
                packet_dict = eval(f.readline())  # Convert string back to dict
                return {k: v for k, v in packet_dict.items() if v is not None}
        except FileNotFoundError:
            logging.error(f"File {file_path} not found. Returning empty record.")
            return {}

    def os_deceive(self):
        """ Intercepts network packets and returns deceptive responses. """
        template_dict = {
            "arp": self.load_file("arp"),
            "tcp": self.load_file("tcp"),
            "udp": self.load_file("udp"),
            "icmp": self.load_file("icmp"),
        }
        logging.info(f"{self.os} deception templates loaded.")

        while True:
            try:
                raw_pkt, _ = self.conn.sock.recvfrom(65565)
            except socket.error as e:
                logging.error(f"Socket error: {e}")
                continue

            pkt = Packet(packet=raw_pkt)
            pkt.unpack()
            proc = pkt.get_proc()

            if proc == "tcp":
                self._handle_port_knocking(pkt)

            if self._should_deceive(pkt):
                rsp = deceived_pkt_synthesis(proc, pkt, template_dict)
                if rsp:
                    logging.info(f"Sending deceptive {proc} packet.")
                    self.conn.sock.send(rsp)

    def _parse_ethernet_ip(self, packet):
        """ Parses Ethernet and IP headers. """
        eth_header = packet[:settings.ETH_HEADER_LEN]
        eth = struct.unpack("!6s6sH", eth_header)
        eth_protocol = socket.ntohs(eth[2])

        ip_header = packet[settings.ETH_HEADER_LEN: settings.ETH_HEADER_LEN + settings.IP_HEADER_LEN]
        _, _, _, _, _, _, PROTOCOL, _, src_IP, dest_IP = struct.unpack("!BBHHHBBH4s4s", ip_header)

        return eth_protocol, src_IP, dest_IP, PROTOCOL

    def _parse_tcp(self, packet):
        """ Parses TCP headers. """
        tcp_header = packet[
            settings.ETH_HEADER_LEN + settings.IP_HEADER_LEN: settings.ETH_HEADER_LEN + settings.IP_HEADER_LEN + settings.TCP_HEADER_LEN
        ]
        src_port, dest_port, _, _, _, flags, _, _, _ = struct.unpack("!HHLLBBHHH", tcp_header)
        return src_port, dest_port, flags

    def _write_record(self, filename, data):
        """ Writes recorded packets to a file. """
        try:
            with open(filename, "w", encoding="utf-8") as f:
                f.write(str(data))
        except IOError as e:
            logging.error(f"Error writing to file {filename}: {e}")

    def _handle_port_knocking(self, pkt):
        """ Handles port knocking authentication. """
        if pkt.l3_field["dest_IP"] == Packet.ip_str2byte(self.host) and pkt.l4_field["dest_port"] in settings.FREE_PORT:
            return

        self.add_knocking_history(pkt)
        if self.verify_knocking(pkt):
            src = ip_byte2str(pkt.l3_field["src_IP"])
            self.white_list[pkt.l3_field["src_IP"]] = datetime.now()
            logging.info(f"Added {src} to white list.")

    def _should_deceive(self, pkt):
        """ Determines if a packet should be deceived. """
        return (
            (pkt.l3 == "ip" and pkt.l3_field["dest_IP"] == socket.inet_aton(self.host))
            or (pkt.l3 == "arp" and pkt.l3_field["recv_ip"] == socket.inet_aton(self.host))
        )
