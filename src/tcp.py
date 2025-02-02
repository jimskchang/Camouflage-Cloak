import socket
import struct
import array
import time
import os

import src.settings as settings
from src.Packet import Packet


class TcpConnect:
    def __init__(self, host):
        self.dip = host
        self.mac = self.get_mac_address(settings.CLOAK_NIC)
        self.sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
        self.sock.bind((settings.CLOAK_NIC, 0))

    @staticmethod
    def get_mac_address(nic):
        """Retrieves MAC address for the given NIC interface."""
        try:
            with open(f'/sys/class/net/{nic}/address', 'r') as f:
                mac = f.readline().strip()
                return Packet.mac_str2byte(mac)
        except FileNotFoundError:
            raise ValueError(f"ERROR: NIC '{nic}' not found. Please update settings.py.")

    def build_tcp_header_from_reply(self, tcp_len, seq, ack_num, src_port, dest_port, src_IP, dest_IP, flags, options=None):
        """Constructs a TCP reply header with optional TCP options."""
        offset = (tcp_len // 4) << 4
        reply_tcp_header = struct.pack('!HHIIBBHHH', 
                                       src_port, dest_port, seq, ack_num, offset, flags, 0, 0, 0)

        if options:
            reply_tcp_header += options

        pseudo_hdr = struct.pack('!4s4sBBH', src_IP, dest_IP, 0, socket.IPPROTO_TCP, len(reply_tcp_header))
        checksum = getTCPChecksum(pseudo_hdr + reply_tcp_header)
        reply_tcp_header = reply_tcp_header[:16] + struct.pack('H', checksum) + reply_tcp_header[18:]

        return reply_tcp_header


def os_build_tcp_header_from_reply(tcp_len, seq, ack_num, src_port, dest_port, src_IP, dest_IP, flags, window, reply_tcp_option):
    """Builds a full TCP header with OS-level deception options."""
    offset = (tcp_len // 4) << 4
    reply_tcp_header = struct.pack('!HHIIBBHHH', 
                                   src_port, dest_port, seq, ack_num, offset, flags, window, 0, 0)
    reply_tcp_header += reply_tcp_option

    pseudo_hdr = struct.pack('!4s4sBBH', src_IP, dest_IP, 0, socket.IPPROTO_TCP, len(reply_tcp_header))
    checksum = getTCPChecksum(pseudo_hdr + reply_tcp_header)
    reply_tcp_header = reply_tcp_header[:16] + struct.pack('H', checksum) + reply_tcp_header[18:]

    return reply_tcp_header


def getIPChecksum(data):
    """Computes IP header checksum."""
    packet_sum = sum((data[i] << 8) + data[i + 1] for i in range(0, len(data), 2))
    packet_sum = (packet_sum >> 16) + (packet_sum & 0xffff)
    packet_sum = ~packet_sum & 0xffff
    return packet_sum


def getTCPChecksum(packet):
    """Computes TCP checksum."""
    if len(packet) % 2 != 0:
        packet += b'\0'

    res = sum(array.array("H", packet))
    res = (res >> 16) + (res & 0xffff)
    res += res >> 16

    return (~res) & 0xffff


def unpack_tcp_option(tcp_option):
    """Unpacks TCP options from a raw TCP header."""
    start_ptr = 0
    kind_seq = []
    option_val = {
        'padding': [],
        'mss': None,
        'shift_count': None,
        'sack_permitted': None,
        'ts_val': None,
        'ts_echo_reply': None
    }

    while start_ptr < len(tcp_option):
        kind = tcp_option[start_ptr]
        start_ptr += 1

        if kind == 1:  # No Operation (NOP)
            option_val['padding'].append(kind)
            kind_seq.append(kind)

        elif kind == 2:  # Maximum Segment Size (MSS)
            length = tcp_option[start_ptr]
            start_ptr += 1
            option_val['mss'] = struct.unpack('!H', tcp_option[start_ptr:start_ptr + 2])[0]
            start_ptr += 2
            kind_seq.append(kind)

        elif kind == 3:  # Window Scale
            length = tcp_option[start_ptr]
            start_ptr += 1
            option_val['shift_count'] = tcp_option[start_ptr]
            start_ptr += 1
            kind_seq.append(kind)

        elif kind == 4:  # SACK Permitted
            length = tcp_option[start_ptr]
            start_ptr += 1
            option_val['sack_permitted'] = True
            kind_seq.append(kind)

        elif kind == 8:  # Timestamps
            length = tcp_option[start_ptr]
            start_ptr += 1
            option_val['ts_val'], option_val['ts_echo_reply'] = struct.unpack('!LL', tcp_option[start_ptr:start_ptr + 8])
            start_ptr += 8
            kind_seq.append(kind)

    return option_val, kind_seq


def pack_tcp_option(option_val, kind_seq):
    """Packs TCP options into a properly formatted header."""
    reply_tcp_option = b''

    for kind in kind_seq:
        if kind == 2:  # MSS
            reply_tcp_option += struct.pack('!BBH', 2, 4, option_val['mss'])

        elif kind == 3:  # Window Scale
            reply_tcp_option += struct.pack('!BBB', 3, 3, option_val['shift_count'])

        elif kind == 4:  # SACK Permitted
            reply_tcp_option += struct.pack('!BB', 4, 2)

        elif kind == 8:  # Timestamps
            ts_val = int(time.time())
            reply_tcp_option += struct.pack('!BBLL', 8, 10, ts_val, option_val['ts_echo_reply'])

        elif kind == 1:  # NOP (Padding)
            reply_tcp_option += struct.pack('!B', 1)

    return reply_tcp_option


def byte2mac(mac_byte):
    """Converts MAC byte format to human-readable string."""
    return "%02x:%02x:%02x:%02x:%02x:%02x" % struct.unpack("BBBBBB", mac_byte)


def byte2ip(ip_byte):
    """Converts IP byte format to human-readable string."""
    return socket.inet_ntoa(ip_byte)
