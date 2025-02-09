import logging
import socket
import struct
from src import settings

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s]: %(message)s")

class Packet:
    def __init__(self, packet=b"", proc=None, l2_field=None, l3_field=None, l4_field=None, data=""):
        self.packet = packet
        self.l3 = proc if proc in settings.L3_PROC else "ip"
        self.l4 = proc if proc in settings.L4_PROC else ""
        self.l2_header = b""
        self.l3_header = b""
        self.l4_header = b""
        self.l2_field = l2_field or {}
        self.l3_field = l3_field or {}
        self.l4_field = l4_field or {}
        self.data = data

    def unpack(self) -> None:
        """ Unpacks all headers: L2, L3, and L4 """
        self.unpack_l2_header()
        self.unpack_l3_header(self.l3)
        if self.l4:
            self.unpack_l4_header(self.l4)

    def unpack_l2_header(self) -> None:
        """ Unpacks the Ethernet (Layer 2) header """
        try:
            self.l2_header = self.packet[:settings.ETH_HEADER_LEN]
            eth = struct.unpack("!6s6sH", self.l2_header)
            eth_dMAC, eth_sMAC, eth_protocol = eth

            if eth_protocol == 0x0800:
                self.l3 = "ip"
            elif eth_protocol == 0x0806:
                self.l3 = "arp"
            else:
                self.l3 = "others"
                logging.warning(f"Unknown Ethernet protocol detected: {eth_protocol}")

            self.l2_field = {
                "dMAC": eth_dMAC,
                "sMAC": eth_sMAC,
                "protocol": eth_protocol,
            }
        except struct.error as e:
            logging.error(f"Error unpacking L2 header: {e}")

    def unpack_l3_header(self, l3) -> None:
        """ Unpacks the L3 (Network Layer) header based on type """
        if l3 == "ip":
            self.unpack_ip_header()
        elif l3 == "arp":
            self.unpack_arp_header()

    def unpack_l4_header(self, l4) -> None:
        """ Unpacks the L4 (Transport Layer) header based on type """
        if l4 == "tcp":
            self.unpack_tcp_header()
        elif l4 == "udp":
            self.unpack_udp_header()
        elif l4 == "icmp":
            self.unpack_icmp_header()

    def unpack_ip_header(self) -> None:
        """ Unpacks the IPv4 header """
        try:
            self.l3_header = self.packet[settings.ETH_HEADER_LEN : settings.ETH_HEADER_LEN + settings.IP_HEADER_LEN]
            ip_header = struct.unpack("!BBHHHBBH4s4s", self.l3_header)

            self.l3_field = {
                "version_ihl": ip_header[0],
                "tos": ip_header[1],
                "total_length": ip_header[2],
                "id": ip_header[3],
                "flags_fragment_offset": ip_header[4],
                "ttl": ip_header[5],
                "protocol": ip_header[6],
                "header_checksum": ip_header[7],
                "src_IP": socket.inet_ntoa(ip_header[8]),
                "dest_IP": socket.inet_ntoa(ip_header[9]),
            }

            if self.l3_field["protocol"] == 1:
                self.l4 = "icmp"
            elif self.l3_field["protocol"] == 6:
                self.l4 = "tcp"
            elif self.l3_field["protocol"] == 17:
                self.l4 = "udp"
        except struct.error as e:
            logging.error(f"Error unpacking IP header: {e}")

    def unpack_tcp_header(self) -> None:
        """ Unpacks the TCP header """
        try:
            offset = settings.ETH_HEADER_LEN + settings.IP_HEADER_LEN
            self.l4_header = self.packet[offset : offset + settings.TCP_HEADER_LEN]
            tcp_header = struct.unpack("!HHLLBBHHH", self.l4_header)

            data_offset = (tcp_header[4] >> 4) * 4
            self.l4_field = {
                "src_port": tcp_header[0],
                "dest_port": tcp_header[1],
                "seq": tcp_header[2],
                "ack_num": tcp_header[3],
                "data_offset": data_offset,
                "flags": tcp_header[5],
                "window": tcp_header[6],
                "checksum": tcp_header[7],
                "urgent_ptr": tcp_header[8],
            }
        except struct.error as e:
            logging.error(f"Error unpacking TCP header: {e}")

    def unpack_udp_header(self) -> None:
        """ Unpacks the UDP header """
        try:
            offset = settings.ETH_HEADER_LEN + settings.IP_HEADER_LEN
            self.l4_header = self.packet[offset : offset + settings.UDP_HEADER_LEN]
            udp_header = struct.unpack("!HHHH", self.l4_header)

            self.l4_field = {
                "src_port": udp_header[0],
                "dest_port": udp_header[1],
                "length": udp_header[2],
                "checksum": udp_header[3],
            }
        except struct.error as e:
            logging.error(f"Error unpacking UDP header: {e}")

    def unpack_icmp_header(self) -> None:
        """ Unpacks the ICMP header """
        try:
            offset = settings.ETH_HEADER_LEN + settings.IP_HEADER_LEN
            self.l4_header = self.packet[offset : offset + settings.ICMP_HEADER_LEN]
            icmp_header = struct.unpack("!BBHHH", self.l4_header)

            self.l4_field = {
                "type": icmp_header[0],
                "code": icmp_header[1],
                "checksum": icmp_header[2],
                "id": icmp_header[3],
                "sequence": icmp_header[4],
            }
        except struct.error as e:
            logging.error(f"Error unpacking ICMP header: {e}")

    @staticmethod
    def calculate_checksum(data: bytes) -> int:
        """ Calculates checksum for IP, TCP, and UDP """
        checksum = 0
        if len(data) % 2:
            data += b"\x00"

        for i in range(0, len(data), 2):
            word = (data[i] << 8) + data[i + 1]
            checksum += word

        checksum = (checksum >> 16) + (checksum & 0xFFFF)
        checksum = ~checksum & 0xFFFF
        return checksum

    @staticmethod
    def mac_str_to_bytes(mac_str: str) -> bytes:
        """ Converts MAC address string to bytes """
        return bytes.fromhex(mac_str.replace(":", ""))

    @staticmethod
    def ip_str_to_bytes(ip_str: str) -> bytes:
        """ Converts an IP string to bytes """
        return socket.inet_aton(ip_str)

    def get_proc(self) -> str:
        """ Returns the highest protocol level in the packet """
        return self.l4 if self.l4 else self.l3
        
