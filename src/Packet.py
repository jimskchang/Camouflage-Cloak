import logging
import socket
import struct
import array
import src.settings as settings

class Packet:
    def __init__(self, packet=b'', proc=None, l2_field=None, l3_field=None, l4_field=None, data=''):
        """
        Initializes a Packet object for handling network packet structures.
        Supports Ethernet (L2), IP/ARP (L3), and TCP/UDP/ICMP (L4) processing.
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
        """Unpacks L2, L3, and L4 headers based on packet type."""
        self.unpack_l2_header()
        self.unpack_l3_header(self.l3)
        if self.l4:
            self.unpack_l4_header(self.l4)

    def unpack_l2_header(self) -> None:
        """Unpacks Ethernet (Layer 2) header to extract MAC addresses and protocol type."""
        self.l2_header = self.packet[:settings.ETH_HEADER_LEN]
        eth_dMAC, eth_sMAC, eth_protocol = struct.unpack('!6s6sH', self.l2_header)
        self.l3 = 'ip' if eth_protocol == 0x0800 else 'arp' if eth_protocol == 0x0806 else 'others'
        self.l2_field = {'dMAC': eth_dMAC, 'sMAC': eth_sMAC, 'protocol': eth_protocol}

    def unpack_l3_header(self, l3) -> None:
        """Unpacks Layer 3 header based on IP or ARP type."""
        if l3 == 'ip':
            self.unpack_ip_header()
        elif l3 == 'arp':
            self.unpack_arp_header()

    def unpack_l4_header(self, l4) -> None:
        """Unpacks Layer 4 headers based on TCP, UDP, or ICMP type."""
        if l4 == 'tcp':
            self.unpack_tcp_header()
        elif l4 == 'udp':
            self.unpack_udp_header()
        elif l4 == 'icmp':
            self.unpack_icmp_header()

    def unpack_arp_header(self) -> None:
        """Unpacks ARP header for address resolution protocol handling."""
        self.l3_header = self.packet[settings.ETH_HEADER_LEN: settings.ETH_HEADER_LEN + settings.ARP_HEADER_LEN]
        hw_type, proto_type, hw_size, proto_size, opcode, sender_mac, sender_ip, recv_mac, recv_ip = struct.unpack('!HHBBH6s4s6s4s', self.l3_header)
        self.l3_field = {'hw_type': hw_type, 'proto_type': proto_type, 'hw_size': hw_size, 'proto_size': proto_size,
                         'opcode': opcode, 'sender_mac': sender_mac, 'sender_ip': sender_ip, 'recv_mac': recv_mac, 'recv_ip': recv_ip}

    def unpack_ip_header(self) -> None:
        """Unpacks IPv4 header and determines the next-layer protocol."""
        self.l3_header = self.packet[settings.ETH_HEADER_LEN: settings.ETH_HEADER_LEN + settings.IP_HEADER_LEN]
        fields = struct.unpack('!BBHHHBBH4s4s', self.l3_header)
        IHL_VERSION, TYPE_OF_SERVICE, total_len, pktID, FRAGMENT_STATUS, TIME_TO_LIVE, PROTOCOL, check_sum_of_hdr, src_IP, dest_IP = fields
        self.l4 = {1: 'icmp', 6: 'tcp', 17: 'udp'}.get(PROTOCOL, 'others')
        self.l3_field = {'IHL_VERSION': IHL_VERSION, 'TYPE_OF_SERVICE': TYPE_OF_SERVICE, 'total_len': total_len,
                         'pktID': pktID, 'FRAGMENT_STATUS': FRAGMENT_STATUS, 'TIME_TO_LIVE': TIME_TO_LIVE,
                         'PROTOCOL': PROTOCOL, 'check_sum_of_hdr': check_sum_of_hdr, 'src_IP': src_IP, 'dest_IP': dest_IP}

    def unpack_tcp_header(self) -> None:
        """Unpacks TCP header and extracts essential TCP parameters."""
        tcp_header_start = settings.ETH_HEADER_LEN + settings.IP_HEADER_LEN
        self.l4_header = self.packet[tcp_header_start:tcp_header_start + settings.TCP_HEADER_LEN]
        src_port, dest_port, seq, ack_num, offset_reserved, flags, window, checksum, urgent_ptr = struct.unpack('!HHLLBBHHH', self.l4_header)
        tcp_len = (offset_reserved >> 4) * 4  # Extract TCP header length
        self.l4_field = {'src_port': src_port, 'dest_port': dest_port, 'seq': seq, 'ack_num': ack_num,
                         'offset': offset_reserved, 'flags': flags, 'window': window, 'checksum': checksum,
                         'urgent_ptr': urgent_ptr, 'tcp_len': tcp_len}

    def unpack_icmp_header(self) -> None:
        """Unpacks ICMP header fields."""
        icmp_header_start = settings.ETH_HEADER_LEN + settings.IP_HEADER_LEN
        self.l4_header = self.packet[icmp_header_start:icmp_header_start + settings.ICMP_HEADER_LEN]
        icmp_type, code, checksum, ID, seq = struct.unpack('!BBHHH', self.l4_header)
        self.l4_field = {'icmp_type': icmp_type, 'code': code, 'checksum': checksum, 'ID': ID, 'seq': seq}

    def unpack_udp_header(self):
    """Unpacks UDP headers and stores extracted fields."""
    udp_header_start = settings.ETH_HEADER_LEN + settings.IP_HEADER_LEN
    self.l4_header = self.packet[udp_header_start:udp_header_start + settings.UDP_HEADER_LEN]

    src_port, dest_port, length, checksum = struct.unpack('!HHHH', self.l4_header)

    self.l4_field = {
        'src_port': src_port,
        'dest_port': dest_port,
        'length': length,
        'checksum': checksum
    }

    @staticmethod
    def getTCPChecksum(packet: bytes) -> int:
        """Calculates TCP checksum for validation and response handling."""
        if len(packet) % 2 != 0:
            packet += b'\0'
        res = sum(array.array("H", packet))
        res = (res >> 16) + (res & 0xffff)
        res += res >> 16
        return (~res) & 0xffff

    @staticmethod
    def getUDPChecksum(data: bytes) -> int:
        """Calculates UDP checksum for integrity verification."""
        checksum = 0
        data_len = len(data)
        if data_len % 2:
            data_len += 1
            data += struct.pack('!B', 0)
        for i in range(0, data_len, 2):
            w = (data[i] << 8) + (data[i + 1])
            checksum += w
        checksum = (checksum >> 16) + (checksum & 0xFFFF)
        checksum = ~checksum & 0xFFFF
        return checksum
