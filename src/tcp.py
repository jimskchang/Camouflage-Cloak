import socket
import binascii
import struct
import array
import time
import src.settings as settings


class TcpConnect:
    def __init__(self, host):
        """
        Initializes the TcpConnect class with the target IP address.
        Creates a raw socket for packet transmission.
        """
        self.dip = host  # Destination IP

        # Dynamically retrieve MAC address
        self.mac = self.get_mac_address(settings.NIC)

        # Create raw socket for packet manipulation
        self.sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
        self.sock.bind((settings.NIC, 0))

    @staticmethod
    def get_mac_address(nic):
        """Retrieves the MAC address of the specified network interface."""
        try:
            with open(f"/sys/class/net/{nic}/address") as f:
                mac = f.read().strip().replace(":", "")
                return binascii.unhexlify(mac)
        except FileNotFoundError:
            return b'\x00\x50\x56\xb0\x10\xe9'  # Default fallback MAC
        except ValueError:
            return b'\x00\x00\x00\x00\x00\x00'  # Invalid MAC, use null

    def build_tcp_header(self, tcp_len, seq, ack_num, src_port, dest_port, src_IP, dest_IP, flags):
        """
        Builds a TCP header from a reply.
        """
        offset = tcp_len << 4
        tcp_header = struct.pack('!HHIIBBHHH', src_port, dest_port, seq, ack_num, offset, flags, 0, 0, 0)

        # Calculate TCP checksum
        pseudo_hdr = struct.pack('!4s4sBBH', src_IP, dest_IP, 0, socket.IPPROTO_TCP, len(tcp_header))
        checksum = calculate_checksum(pseudo_hdr + tcp_header)

        # Insert checksum into TCP header
        return tcp_header[:16] + struct.pack('H', checksum) + tcp_header[18:]


def build_tcp_header_with_options(tcp_len, seq, ack_num, src_port, dest_port, src_IP, dest_IP, flags, window, options):
    """
    Builds a TCP header with optional TCP options.
    """
    offset = tcp_len << 4
    tcp_header = struct.pack('!HHIIBBHHH', src_port, dest_port, seq, ack_num, offset, flags, window, 0, 0)
    tcp_header_with_options = tcp_header + options

    # Calculate checksum
    pseudo_hdr = struct.pack('!4s4sBBH', src_IP, dest_IP, 0, socket.IPPROTO_TCP, len(tcp_header_with_options))
    checksum = calculate_checksum(pseudo_hdr + tcp_header_with_options)

    return tcp_header_with_options[:16] + struct.pack('H', checksum) + tcp_header_with_options[18:]


def calculate_checksum(data):
    """
    Computes the checksum of a given data packet (IP or TCP).
    """
    if len(data) % 2 != 0:
        data += b'\0'

    res = sum(array.array("H", data))
    res = (res >> 16) + (res & 0xffff)
    res += res >> 16

    return (~res) & 0xffff


def unpack_tcp_option(tcp_option):
    """
    Unpacks TCP options from a given TCP packet.
    """
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
        kind, = struct.unpack('!B', tcp_option[start_ptr:start_ptr + 1])
        start_ptr += 1

        if kind == 1:  # No-Operation (NOP)
            option_val['padding'].append(kind)
            kind_seq.append(kind)
        elif kind in {2, 3, 4, 8}:  # Options requiring additional data
            length, = struct.unpack('!B', tcp_option[start_ptr:start_ptr + 1])
            start_ptr += 1
            if kind == 2:
                option_val['mss'], = struct.unpack('!H', tcp_option[start_ptr:start_ptr + length - 2])
            elif kind == 3:
                option_val['shift_count'], = struct.unpack('!B', tcp_option[start_ptr:start_ptr + length - 2])
            elif kind == 4:
                option_val['sack_permitted'] = True
            elif kind == 8:
                option_val['ts_val'], option_val['ts_echo_reply'] = struct.unpack('!LL', tcp_option[
                                                                                     start_ptr:start_ptr + length - 2])
            start_ptr += length - 2
            kind_seq.append(kind)

    return option_val, kind_seq


def pack_tcp_option(option_val, kind_seq):
    """
    Packs TCP options into a byte string.
    """
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
        elif kind == 1:  # No-Operation (NOP)
            reply_tcp_option += struct.pack('!B', 1)

    return reply_tcp_option


def mac_to_str(mac_byte):
    """
    Converts a MAC address from bytes to a human-readable string.
    """
    return ":".join(f"{b:02x}" for b in mac_byte)


def ip_to_str(ip_byte):
    """
    Converts an IP address from bytes to a human-readable string.
    """
    return socket.inet_ntoa(ip_byte)
