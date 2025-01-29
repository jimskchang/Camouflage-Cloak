import logging
import socket
import struct
import src.settings as settings


class Packet:
    def __init__(self, packet=b'', proc=None, l2_field=None, l3_field=None, l4_field=None, data=''):
        """
        Packet class for handling network packets at various protocol layers (L2, L3, L4).
        Supports unpacking and repacking of Ethernet, IP, ARP, TCP, UDP, and ICMP packets.
        """
        self.packet = packet
        self.l3 = proc if proc in settings.L3_PROC else 'ip'
        self.l4 = proc if proc in settings.L4_PROC else ''
        self.l2_header = b''
        self.l3_header = b''
        self.l4_header = b''
        self.l2_field = l2_field or {}
        self.l3_field = l3_field or {}
        self.l4_field = l4_field or {}
        self.data = data

    def unpack(self) -> None:
        """ Unpacks the raw packet into L2, L3, and L4 headers. """
        try:
            self.unpack_l2_header()
            self.unpack_l3_header(self.l3)
            if self.l4:
                self.unpack_l4_header(self.l4)
        except Exception as e:
            logging.error(f"Packet unpacking failed: {e}")

    def unpack_l2_header(self) -> None:
        """ Unpacks the Layer 2 (Ethernet) header. """
        try:
            self.l2_header = self.packet[:settings.ETH_HEADER_LEN]
            eth_dMAC, eth_sMAC, eth_protocol = struct.unpack('!6s6sH', self.l2_header)

            self.l3 = {2048: 'ip', 2054: 'arp'}.get(eth_protocol, 'others')

            self.l2_field = {
                'dMAC': eth_dMAC,
                'sMAC': eth_sMAC,
                'protocol': eth_protocol
            }
        except struct.error:
            logging.error("Failed to unpack L2 header: Invalid packet format.")

    def unpack_l3_header(self, l3) -> None:
        """ Unpacks the Layer 3 (Network) header based on the protocol. """
        if l3 == 'ip':
            self.unpack_ip_header()
        elif l3 == 'arp':
            self.unpack_arp_header()

    def unpack_l4_header(self, l4) -> None:
        """ Unpacks the Layer 4 (Transport) header based on the protocol. """
        unpack_methods = {
            'tcp': self.unpack_tcp_header,
            'udp': self.unpack_udp_header,
            'icmp': self.unpack_icmp_header
        }
        unpack_methods.get(l4, lambda: logging.warning("Unknown L4 protocol"))()

    def unpack_ip_header(self) -> None:
        """ Unpacks the IP header. """
        try:
            self.l3_header = self.packet[settings.ETH_HEADER_LEN: settings.ETH_HEADER_LEN + settings.IP_HEADER_LEN]
            (
                IHL_VERSION, TYPE_OF_SERVICE, total_len, pktID, FRAGMENT_STATUS, TIME_TO_LIVE, PROTOCOL,
                check_sum_of_hdr, src_IP, dest_IP
            ) = struct.unpack('!BBHHHBBH4s4s', self.l3_header)

            self.l4 = {1: 'icmp', 6: 'tcp', 17: 'udp'}.get(PROTOCOL, 'others')

            self.l3_field = {
                'IHL_VERSION': IHL_VERSION,
                'TYPE_OF_SERVICE': TYPE_OF_SERVICE,
                'total_len': total_len,
                'pktID': pktID,
                'FRAGMENT_STATUS': FRAGMENT_STATUS,
                'TIME_TO_LIVE': TIME_TO_LIVE,
                'PROTOCOL': PROTOCOL,
                'check_sum_of_hdr': check_sum_of_hdr,
                'src_IP': src_IP,
                'dest_IP': dest_IP
            }
        except struct.error:
            logging.error("Failed to unpack IP header: Invalid packet format.")

    @staticmethod
    def ip_str2byte(ip_str: str) -> bytes:
        """ Converts an IP string (e.g., '192.168.1.1') to a byte representation. """
        try:
            return socket.inet_aton(ip_str)
        except socket.error:
            logging.error(f"Invalid IP address format: {ip_str}")
            return b'\x00\x00\x00\x00'

    @staticmethod
    def mac_str2byte(mac_str: str) -> bytes:
        """ Converts a MAC address string (e.g., 'AA:BB:CC:DD:EE:FF') to bytes. """
        try:
            return bytes.fromhex(mac_str.replace(":", ""))
        except ValueError:
            logging.error(f"Invalid MAC address format: {mac_str}")
            return b'\x00\x00\x00\x00\x00\x00'

    @staticmethod
    def get_checksum(data: bytes) -> int:
        """ Computes the checksum of a given data packet. """
        checksum = 0
        data_len = len(data)
        if data_len % 2:
            data += struct.pack('!B', 0)

        for i in range(0, data_len, 2):
            word = (data[i] << 8) + data[i + 1]
            checksum += word

        checksum = (checksum >> 16) + (checksum & 0xFFFF)
        return ~checksum & 0xFFFF

    def diff_tcp(self, pkt2):
        """ Compares TCP fields between two packets and returns differences. """
        diff = {}

        for field in self.l2_field:
            if self.l2_field[field] != pkt2.l2_field[field]:
                diff[field] = (self.l2_field[field], pkt2.l2_field[field])

        for field in self.l3_field:
            if self.l3_field[field] != pkt2.l3_field[field]:
                diff[field] = (self.l3_field[field], pkt2.l3_field[field])

        for field in self.l4_field:
            if self.l4_field[field] != pkt2.l4_field[field]:
                diff[field] = (self.l4_field[field], pkt2.l4_field[field])

        return diff


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    raw_packet = b'\x00' * 64  # Simulated packet data
    pkt = Packet(raw_packet)
    pkt.unpack()
