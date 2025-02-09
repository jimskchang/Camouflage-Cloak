import socket
import binascii
import struct
import array
import time
import logging
from src import settings

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s]: %(message)s")


class TcpConnect:
    """ Handles raw TCP connections and packet manipulation. """

    def __init__(self, host: str):
        self.dip = host

        # Validate and read NIC MAC address
        self.mac = self._get_mac_address()

        # Initialize raw socket
        self.sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
        self.sock.bind((settings.NIC, 0))

    def _get_mac_address(self):
        """ Reads the MAC address from the NIC file. """
        try:
            with open(settings.NICAddr) as f:
                mac = f.readline().strip()
                return binascii.unhexlify(mac.replace(":", ""))
        except FileNotFoundError:
            logging.error(f"NIC address file {settings.NICAddr} not found.")
            return b"\x00\x00\x00\x00\x00\x00"

    def build_tcp_header_from_reply(self, tcp_len, seq, ack_num, src_port, dest_port, src_IP, dest_IP, flags):
        """ Builds a TCP header based on a response template. """
        offset = tcp_len << 4
        reply_tcp_header = struct.pack("!HHIIBBHHH", src_port, dest_port, seq, ack_num, offset, flags, 0, 0, 0)

        pseudo_hdr = struct.pack("!4s4sBBH", src_IP, dest_IP, 0, socket.IPPROTO_TCP, len(reply_tcp_header))
        checksum = calculate_tcp_checksum(pseudo_hdr + reply_tcp_header)

        return reply_tcp_header[:16] + struct.pack("H", checksum) + reply_tcp_header[18:]


def os_build_tcp_header_from_reply(tcp_len, seq, ack_num, src_port, dest_port, src_IP, dest_IP, flags, window,
                                   reply_tcp_option):
    """ Builds a TCP header for OS deception. """
    offset = tcp_len << 4
    reply_tcp_header = struct.pack("!HHIIBBHHH", src_port, dest_port, seq, ack_num, offset, flags, window, 0, 0)
    reply_tcp_header_option = reply_tcp_header + reply_tcp_option

    pseudo_hdr = struct.pack("!4s4sBBH", src_IP, dest_IP, 0, socket.IPPROTO_TCP, len(reply_tcp_header_option))
    checksum = calculate_tcp_checksum(pseudo_hdr + reply_tcp_header_option)

    return reply_tcp_header_option[:16] + struct.pack("H", checksum) + reply_tcp_header_option[18:]


def calculate_ip_checksum(data):
    """ Calculates the IP checksum. """
    packet_sum = sum((data[i] << 8) + data[i + 1] for i in range(0, len(data), 2))
    packet_sum = (packet_sum >> 16) + (packet_sum & 0xffff)
    packet_sum = ~packet_sum & 0xffff
    return packet_sum


def calculate_tcp_checksum(packet):
    """ Calculates the TCP checksum. """
    if len(packet) % 2 != 0:
        packet += b"\0"

    res = sum(array.array("H", packet))
    res = (res >> 16) + (res & 0xffff)
    res += res >> 16

    return (~res) & 0xffff


def unpack_tcp_option(tcp_option):
    """ Unpacks TCP options from a raw TCP header. """
    start_ptr = 0
    kind_seq = []
    option_val = {
        "padding": [],
        "mss": None,
        "shift_count": None,
        "sack_permitted": None,
        "ts_val": None,
        "ts_echo_reply": None,
    }

    while start_ptr < len(tcp_option):
        kind = tcp_option[start_ptr]
        start_ptr += 1

        if kind == 1:  # No operation (NOP)
            option_val["padding"].append(kind)
            kind_seq.append(kind)

        elif kind == 2:  # Maximum Segment Size (MSS)
            length = tcp_option[start_ptr]
            start_ptr += 1
            option_val["mss"] = struct.unpack("!H", tcp_option[start_ptr:start_ptr + 2])[0]
            start_ptr += 2
            kind_seq.append(kind)

        elif kind == 3:  # Window Scale
            length = tcp_option[start_ptr]
            start_ptr += 1
            option_val["shift_count"] = tcp_option[start_ptr]
            start_ptr += 1
            kind_seq.append(kind)

        elif kind == 4:  # SACK permitted
            option_val["sack_permitted"] = True
            start_ptr += 1
            kind_seq.append(kind)

        elif kind == 8:  # Timestamp
            length = tcp_option[start_ptr]
            start_ptr += 1
            option_val["ts_val"], option_val["ts_echo_reply"] = struct.unpack("!LL", tcp_option[start_ptr:start_ptr + 8])
            start_ptr += 8
            kind_seq.append(kind)

    return option_val, kind_seq


def pack_tcp_option(option_val, kind_seq):
    """ Packs TCP options based on provided values. """
    reply_tcp_option = b""

    for kind in kind_seq:
        if kind == 2:
            reply_tcp_option += struct.pack("!BBH", 2, 4, option_val["mss"])

        elif kind == 4:
            reply_tcp_option += struct.pack("!BB", 4, 2)

        elif kind == 8:
            ts_val = int(time.time())
            reply_tcp_option += struct.pack("!BBLL", 8, 10, ts_val, option_val["ts_echo_reply"])

        elif kind == 1:
            reply_tcp_option += struct.pack("!B", 1)

        elif kind == 3:
            reply_tcp_option += struct.pack("!BBB", 3, 3, option_val["shift_count"])

    return reply_tcp_option


def byte_to_mac(mac_byte):
    """ Converts a MAC address from bytes to a string format. """
    return ":".join(f"{b:02x}" for b in mac_byte)


def byte_to_ip(ip_byte):
    """ Converts an IP address from bytes to a string format. """
    return socket.inet_ntoa(ip_byte)
