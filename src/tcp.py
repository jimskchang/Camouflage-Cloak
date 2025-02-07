import socket
import binascii
import struct
import array
import time
import os
import sys

# Ensure the `src` directory is in the Python module path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

try:
    import settings  # Import settings after modifying the path
except ImportError:
    print("Warning: Failed to import settings.py. Ensure it exists and is in the correct directory.")
    settings = None

class TcpConnect:
    def __init__(self, host):
        self.dip = host

        if settings:
            try:
                with open(settings.NICAddr) as f:
                    mac = f.readline()
                    self.mac = binascii.unhexlify(str.encode(''.join(mac.split(':')))[:-1])
            except FileNotFoundError:
                print(f"Warning: Unable to read NIC address from {settings.NICAddr}. Ensure the path is correct.")
                self.mac = b'\x00\x00\x00\x00\x00\x00'  # Default MAC address placeholder

            self.sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
            self.sock.bind((settings.NIC, 0))

    def build_tcp_header_from_reply(self, tcp_len, seq, ack_num, src_port, dest_port, src_IP, dest_IP, flags):
        """Builds a TCP header for a reply packet."""
        offset = tcp_len << 4
        reply_tcp_header = struct.pack('!HHIIBBHHH', src_port, dest_port, seq, ack_num, offset, flags, 0, 0, 0)
        pseudo_hdr = struct.pack('!4s4sBBH', src_IP, dest_IP, 0, socket.IPPROTO_TCP, len(reply_tcp_header))
        checksum = get_tcp_checksum(pseudo_hdr + reply_tcp_header)
        reply_tcp_header = reply_tcp_header[:16] + struct.pack('H', checksum) + reply_tcp_header[18:]

        return reply_tcp_header

def get_tcp_checksum(packet):
    """Calculates the checksum for a TCP segment."""
    if len(packet) % 2 != 0:
        packet += b'\0'

    res = sum(array.array("H", packet))
    res = (res >> 16) + (res & 0xffff)
    res += res >> 16

    return (~res) & 0xffff

def get_ip_checksum(data):
    """Calculates the checksum for an IP header."""
    packet_sum = 0
    for index in range(0, len(data), 2):
        word = (data[index] << 8) + (data[index + 1])
        packet_sum += word
    packet_sum = (packet_sum >> 16) + (packet_sum & 0xffff)
    packet_sum = ~packet_sum & 0xffff
    return packet_sum

__all__ = ["TcpConnect", "get_tcp_checksum", "get_ip_checksum"]
