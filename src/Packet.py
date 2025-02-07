import logging
import socket
import struct
import os

# Ensure settings is properly imported
try:
    import src.settings as settings
except ImportError:
    logging.warning("Failed to import settings.py. Using default values.")
    settings = None

# Default protocol processing lists (if missing from settings.py)
L3_PROC = getattr(settings, "L3_PROC", ['ip', 'arp'])
L4_PROC = getattr(settings, "L4_PROC", ['tcp', 'udp', 'icmp'])

class Packet:
    def __init__(self, packet=b'', proc=None, l2_field=None, l3_field=None, l4_field=None, data=''):
        self.packet = packet
        self.l3 = proc if proc in L3_PROC else 'ip'
        self.l4 = proc if proc in L4_PROC else ''
        self.l2_header = b''
        self.l3_header = b''
        self.l4_header = b''
        self.l2_field = l2_field or {}
        self.l3_field = l3_field or {}
        self.l4_field = l4_field or {}
        self.data = data

    def unpack(self) -> None:
        """ Unpacks the received packet into L2, L3, and L4 headers. """
        self.unpack_l2_header()
        self.unpack_l3_header()

        if self.l3 == 'arp':  # ARP has no L4 header, so skip L4 processing
            return

        if self.l4:
            self.unpack_l4_header()

    def unpack_l2_header(self) -> None:
        """ Unpacks Ethernet (L2) header. """
        self.l2_header = self.packet[:settings.ETH_HEADER_LEN]
        eth = struct.unpack('!6s6sH', self.l2_header)
        eth_dMAC, eth_sMAC, eth_protocol = eth

        if eth_protocol == 0x0800:
            self.l3 = 'ip'
        elif eth_protocol == 0x0806:
            self.l3 = 'arp'
        else:
            self.l3 = 'others'

        self.l2_field = {
            'dMAC': convert_bytes_to_mac(eth_dMAC),
            'sMAC': convert_bytes_to_mac(eth_sMAC),
            'protocol': eth_protocol
        }

    def unpack_l3_header(self) -> None:
        """ Unpacks Layer 3 header based on protocol type. """
        if self.l3 == 'ip':
            self.unpack_ip_header()
        elif self.l3 == 'arp':
            self.unpack_arp_packet()  # Correct ARP processing

    def unpack_l4_header(self) -> None:
        """ Unpacks Layer 4 headers based on protocol type. """
        if self.l4 == 'tcp':
            self.unpack_tcp_header()
        elif self.l4 == 'udp':
            self.unpack_udp_header()
        elif self.l4 == 'icmp':
            self.unpack_icmp_header()

    def unpack_ip_header(self) -> None:
        """ Unpacks IP header and determines Layer 4 protocol. """
        ip_start = settings.ETH_HEADER_LEN
        ip_end = ip_start + settings.IP_HEADER_LEN
        self.l3_header = self.packet[ip_start:ip_end]

        fields = struct.unpack('!BBHHHBBH4s4s', self.l3_header)
        IHL_VERSION, _, total_len, _, _, _, PROTOCOL, _, src_IP, dest_IP = fields

        if PROTOCOL == 1:
            self.l4 = 'icmp'
        elif PROTOCOL == 6:
            self.l4 = 'tcp'
        elif PROTOCOL == 17:
            self.l4 = 'udp'
        else:
            self.l4 = 'others'

        self.l3_field = {
            'IHL_VERSION': IHL_VERSION,
            'total_len': total_len,
            'PROTOCOL': PROTOCOL,
            'src_IP': convert_bytes_to_ip(src_IP),
            'dest_IP': convert_bytes_to_ip(dest_IP)
        }

    def unpack_arp_packet(self) -> None:
        """ Unpacks ARP header and stores relevant fields. """
        arp_start = settings.ETH_HEADER_LEN
        arp_end = arp_start + settings.ARP_HEADER_LEN
        self.l3_header = self.packet[arp_start:arp_end]

        fields = struct.unpack('!HHBBH6s4s6s4s', self.l3_header)
        hw_type, proto_type, hw_size, proto_size, opcode, sender_mac, sender_ip, target_mac, target_ip = fields

        self.l3_field = {
            'hw_type': hw_type,
            'proto_type': proto_type,
            'hw_size': hw_size,
            'proto_size': proto_size,
            'opcode': opcode,  # 1 = ARP Request, 2 = ARP Reply
            'sender_mac': convert_bytes_to_mac(sender_mac),
            'sender_ip': convert_bytes_to_ip(sender_ip),
            'target_mac': convert_bytes_to_mac(target_mac),
            'target_ip': convert_bytes_to_ip(target_ip)
        }

        logging.info(f"ARP Packet: {self.l3_field}")

    def unpack_tcp_header(self) -> None:
        """ Unpacks TCP header. """
        tcp_start = settings.ETH_HEADER_LEN + settings.IP_HEADER_LEN
        tcp_end = tcp_start + settings.TCP_HEADER_LEN
        self.l4_header = self.packet[tcp_start:tcp_end]

        fields = struct.unpack('!HHLLBBHHH', self.l4_header)
        src_port, dest_port, seq, ack_num, offset_flags, flags, _, checksum, _ = fields

        tcp_len = (offset_flags >> 4) * 4
        self.l4_field = {
            'src_port': src_port,
            'dest_port': dest_port,
            'seq': seq,
            'ack_num': ack_num,
            'flags': flags,
            'checksum': checksum,
            'tcp_len': tcp_len
        }

    def unpack_udp_header(self) -> None:
        """ Unpacks UDP header. """
        udp_start = settings.ETH_HEADER_LEN + settings.IP_HEADER_LEN
        udp_end = udp_start + settings.UDP_HEADER_LEN
        self.l4_header = self.packet[udp_start:udp_end]

        fields = struct.unpack('!4H', self.l4_header)
        src_port, dest_port, udp_len, checksum = fields

        self.l4_field = {
            'src_port': src_port,
            'dest_port': dest_port,
            'udp_len': udp_len,
            'checksum': checksum
        }

    def pack_l3_header(self):
        """ Packs the L3 header based on protocol type. """
        if self.l3 == 'ip':
            self.pack_ip_header()
        self.packet += self.l3_header

    def pack_ip_header(self):
        """ Packs the IP header for outgoing packets. """
        ip_field = self.l3_field
        src_IP_bytes = convert_ip_to_bytes(ip_field['src_IP'])
        dest_IP_bytes = convert_ip_to_bytes(ip_field['dest_IP'])

        pseudo_ip_header = struct.pack(
            '!BBHHHBBH4s4s',
            ip_field['IHL_VERSION'], 0, ip_field['total_len'], 0, 0,
            64, ip_field['PROTOCOL'], 0, src_IP_bytes, dest_IP_bytes
        )
        ip_field['checksum'] = calculate_checksum(pseudo_ip_header)

        self.l3_header = struct.pack(
            '!BBHHHBBH4s4s',
            ip_field['IHL_VERSION'], 0, ip_field['total_len'], 0, 0,
            64, ip_field['PROTOCOL'], ip_field['checksum'], src_IP_bytes, dest_IP_bytes
        )

    def get_proc(self):
        """ Returns the protocol (L3 or L4) being processed. """
        return self.l3 if not self.l4 else self.l4
