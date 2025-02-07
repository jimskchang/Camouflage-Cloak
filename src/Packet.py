import logging
import socket
import struct
import os

# Ensure settings is properly imported
try:
    import settings
except ImportError:
    logging.warning("Failed to import settings.py. Using default values.")
    settings = None

# Provide default values if settings.py is missing
ETH_HEADER_LEN = getattr(settings, "ETH_HEADER_LEN", 14)
IP_HEADER_LEN = getattr(settings, "IP_HEADER_LEN", 20)
ARP_HEADER_LEN = getattr(settings, "ARP_HEADER_LEN", 28)
TCP_HEADER_LEN = getattr(settings, "TCP_HEADER_LEN", 20)
UDP_HEADER_LEN = getattr(settings, "UDP_HEADER_LEN", 8)
ICMP_HEADER_LEN = getattr(settings, "ICMP_HEADER_LEN", 8)
L3_PROC = getattr(settings, "L3_PROC", ['ip', 'arp'])
L4_PROC = getattr(settings, "L4_PROC", ['tcp', 'udp', 'icmp'])

# Utility functions
def convert_bytes_to_mac(mac_bytes):
    return ':'.join(f"{b:02x}" for b in mac_bytes)

def convert_bytes_to_ip(ip_bytes):
    return '.'.join(str(b) for b in ip_bytes)

def convert_ip_to_bytes(ip_str):
    return socket.inet_aton(ip_str)

def calculate_checksum(data):
    return sum(data) & 0xFFFF  # Placeholder checksum function

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

    def unpack(self):
        """ Unpacks the received packet into L2, L3, and L4 headers. """
        if len(self.packet) < ETH_HEADER_LEN:
            logging.error("Packet too small for L2 header.")
            return
        self.unpack_l2_header()
        
        if len(self.packet) < ETH_HEADER_LEN + IP_HEADER_LEN:
            logging.error("Packet too small for L3 header.")
            return
        self.unpack_l3_header()

        if self.l3 != 'arp' and self.l4:
            self.unpack_l4_header()

    def unpack_l3_header(self):
        """ Unpacks Layer 3 header and determines protocol. """
        ip_start = ETH_HEADER_LEN
        ip_end = ip_start + IP_HEADER_LEN
        self.l3_header = self.packet[ip_start:ip_end]

        fields = struct.unpack('!BBHHHBBH4s4s', self.l3_header)
        IHL_VERSION, _, total_len, _, _, _, PROTOCOL, _, src_IP, dest_IP = fields

        self.l4 = {1: 'icmp', 6: 'tcp', 17: 'udp'}.get(PROTOCOL, 'others')

        if self.l4 == 'others':
            logging.warning(f"Unknown L4 protocol detected: {PROTOCOL}")

        self.l3_field = {
            'IHL_VERSION': IHL_VERSION,
            'total_len': total_len,
            'PROTOCOL': PROTOCOL,
            'src_IP': convert_bytes_to_ip(src_IP),
            'dest_IP': convert_bytes_to_ip(dest_IP)
        }

    def unpack_l2_header(self):
        """ Unpacks Ethernet (L2) header. """
        self.l2_header = self.packet[:ETH_HEADER_LEN]
        eth_dMAC, eth_sMAC, eth_protocol = struct.unpack('!6s6sH', self.l2_header)

        self.l3 = {0x0800: 'ip', 0x0806: 'arp'}.get(eth_protocol, 'others')

        self.l2_field = {
            'dMAC': convert_bytes_to_mac(eth_dMAC),
            'sMAC': convert_bytes_to_mac(eth_sMAC),
            'protocol': eth_protocol
        }
