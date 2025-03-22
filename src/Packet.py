import logging
import socket
import struct
import array
import src.settings as settings


class Packet:
    def __init__(self, packet=b'', proc=None, l2_field=None, l3_field=None, l4_field=None, data=''):
        """
        Initializes a packet object to handle different network layers.
        Supports NIC routing and TTL/window from settings or templates.
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
        self.interface = None  # Optional NIC tag (e.g. NIC_PROBE)

    def unpack(self) -> None:
        """Unpacks all layers in order, logs errors safely."""
        try:
            self.unpack_l2_header()
            self.unpack_l3_header(self.l3)
            if self.l4:
                self.unpack_l4_header(self.l4)
        except Exception as e:
            logging.error(f"[Packet] General unpack error: {e}")

    def unpack_l2_header(self) -> None:
        if len(self.packet) < settings.ETH_HEADER_LEN:
            logging.error("[L2] Packet too short for Ethernet header.")
            return
        try:
            self.l2_header = self.packet[:settings.ETH_HEADER_LEN]
            eth_dMAC, eth_sMAC, eth_protocol = struct.unpack('!6s6sH', self.l2_header)
            self.l3 = {0x0800: 'ip', 0x0806: 'arp'}.get(eth_protocol, 'others')
            self.l2_field = {
                'dMAC': eth_dMAC,
                'sMAC': eth_sMAC,
                'protocol': eth_protocol,
            }
        except Exception as e:
            logging.error(f"[L2] Error unpacking Ethernet: {e}")

    def unpack_l3_header(self, l3: str) -> None:
        if l3 == 'ip':
            self.unpack_ip_header()
        elif l3 == 'arp':
            self.unpack_arp_header()

    def unpack_l4_header(self, l4: str) -> None:
        if l4 == 'tcp':
            self.unpack_tcp_header()
        elif l4 == 'udp':
            self.unpack_udp_header()
        elif l4 == 'icmp':
            self.unpack_icmp_header()

    def unpack_arp_header(self) -> None:
        try:
            if len(self.packet) < settings.ETH_HEADER_LEN + settings.ARP_HEADER_LEN:
                raise ValueError("Packet too short for ARP header.")
            self.l3_header = self.packet[settings.ETH_HEADER_LEN : settings.ETH_HEADER_LEN + settings.ARP_HEADER_LEN]
            fields = struct.unpack('!HHBBH6s4s6s4s', self.l3_header)
            self.l3_field = {
                'hw_type': fields[0],
                'proto_type': fields[1],
                'hw_size': fields[2],
                'proto_size': fields[3],
                'opcode': fields[4],
                'sender_mac': fields[5],
                'sender_ip': fields[6],
                'recv_mac': fields[7],
                'recv_ip': fields[8],
            }
        except Exception as e:
            logging.error(f"[ARP] Error unpacking: {e}")

    def unpack_ip_header(self) -> None:
        try:
            if len(self.packet) < settings.ETH_HEADER_LEN + settings.IP_HEADER_LEN:
                raise ValueError("Packet too short for IP header.")
            self.l3_header = self.packet[settings.ETH_HEADER_LEN : settings.ETH_HEADER_LEN + settings.IP_HEADER_LEN]
            fields = struct.unpack('!BBHHHBBH4s4s', self.l3_header)
            self.l4 = {1: 'icmp', 6: 'tcp', 17: 'udp'}.get(fields[6], 'others')
            self.l3_field = {
                'IHL_VERSION': fields[0],
                'TYPE_OF_SERVICE': fields[1],
                'total_len': fields[2],
                'pktID': fields[3],
                'FRAGMENT_STATUS': fields[4],
                'TIME_TO_LIVE': fields[5],
                'PROTOCOL': fields[6],
                'check_sum_of_hdr': fields[7],
                'src_IP': fields[8],
                'dest_IP': fields[9]
            }
        except Exception as e:
            logging.error(f"[IP] Error unpacking: {e}")

    def unpack_tcp_header(self) -> None:
        try:
            tcp_start = settings.ETH_HEADER_LEN + settings.IP_HEADER_LEN
            self.l4_header = self.packet[tcp_start : tcp_start + settings.TCP_HEADER_LEN]
            fields = struct.unpack('!HHLLBBHHH', self.l4_header)
            self.l4_field = {
                'src_port': fields[0],
                'dest_port': fields[1],
                'seq': fields[2],
                'ack_num': fields[3],
                'offset': (fields[4] >> 4) * 4,
                'flags': fields[5],
                'window': fields[6],
                'checksum': fields[7],
                'urgent_ptr': fields[8],
            }
        except Exception as e:
            logging.error(f"[TCP] Error unpacking: {e}")

    def unpack_udp_header(self) -> None:
        try:
            udp_start = settings.ETH_HEADER_LEN + settings.IP_HEADER_LEN
            self.l4_header = self.packet[udp_start : udp_start + settings.UDP_HEADER_LEN]
            fields = struct.unpack('!HHHH', self.l4_header)
            self.l4_field = {
                'src_port': fields[0],
                'dest_port': fields[1],
                'length': fields[2],
                'checksum': fields[3],
            }
        except Exception as e:
            logging.error(f"[UDP] Error unpacking: {e}")

    def unpack_icmp_header(self) -> None:
        try:
            icmp_start = settings.ETH_HEADER_LEN + settings.IP_HEADER_LEN
            self.l4_header = self.packet[icmp_start : icmp_start + settings.ICMP_HEADER_LEN]
            fields = struct.unpack('!BBHHH', self.l4_header)
            self.l4_field = {
                'icmp_type': fields[0],
                'code': fields[1],
                'checksum': fields[2],
                'ID': fields[3],
                'seq': fields[4],
            }
        except Exception as e:
            logging.error(f"[ICMP] Error unpacking: {e}")

    @staticmethod
    def getTCPChecksum(packet: bytes) -> int:
        """Compute checksum for TCP segments."""
        if len(packet) % 2 != 0:
            packet += b'\0'
        res = sum(array.array("H", packet))
        res = (res >> 16) + (res & 0xFFFF)
        res += res >> 16
        return (~res) & 0xFFFF

    @staticmethod
    def getUDPChecksum(data: bytes) -> int:
        """Compute checksum for UDP datagrams."""
        checksum = 0
        if len(data) % 2:
            data += b'\0'
        for i in range(0, len(data), 2):
            checksum += (data[i] << 8) + data[i+1]
        checksum = (checksum >> 16) + (checksum & 0xFFFF)
        return ~checksum & 0xFFFF
