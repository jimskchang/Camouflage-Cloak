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
        self.dip = socket.inet_aton(host)  # Convert host IP to bytes

        # Validate and read NIC MAC address
        self.mac = self._get_mac_address()

        # Initialize raw socket
        try:
            self.sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
            self.sock.bind((settings.NIC, 0))
        except Exception as e:
            logging.error(f"Failed to initialize raw socket: {e}")
            raise

    def _get_mac_address(self):
        """ Reads the MAC address from the NIC file. """
        try:
            with open(settings.NICAddr) as f:
                mac = f.readline().strip()
                return binascii.unhexlify(mac.replace(":", ""))
        except FileNotFoundError:
            logging.error(f"NIC address file {settings.NICAddr} not found.")
            return b"\x00\x00\x00\x00\x00\x00"
        except Exception as e:
            logging.error(f"Error reading MAC address: {e}")
            return b"\x00\x00\x00\x00\x00\x00"

    def build_tcp_header_from_reply(self, tcp_len, seq, ack_num, src_port, dest_port, src_IP, dest_IP, flags):
        """ Builds a TCP header based on a response template. """
        try:
            src_IP = socket.inet_aton(src_IP)  # Convert string IP to bytes
            dest_IP = socket.inet_aton(dest_IP)  # Convert string IP to bytes

            offset = tcp_len << 4
            reply_tcp_header = struct.pack("!HHIIBBHHH", src_port, dest_port, seq, ack_num, offset, flags, 0, 0, 0)

            pseudo_hdr = struct.pack("!4s4sBBH", src_IP, dest_IP, 0, socket.IPPROTO_TCP, len(reply_tcp_header))
            checksum = calculate_tcp_checksum(pseudo_hdr + reply_tcp_header)

            return reply_tcp_header[:16] + struct.pack("H", checksum) + reply_tcp_header[18:]
        except Exception as e:
            logging.error(f"Error building TCP header: {e}")
            return None


def os_build_tcp_header_from_reply(tcp_len, seq, ack_num, src_port, dest_port, src_IP, dest_IP, flags, window,
                                   reply_tcp_option):
    """ Builds a TCP header for OS deception. """
    try:
        src_IP = socket.inet_aton(src_IP)  # Convert string IP to bytes
        dest_IP = socket.inet_aton(dest_IP)  # Convert string IP to bytes

        offset = tcp_len << 4
        reply_tcp_header = struct.pack("!HHIIBBHHH", src_port, dest_port, seq, ack_num, offset, flags, window, 0, 0)
        reply_tcp_header_option = reply_tcp_header + reply_tcp_option

        pseudo_hdr = struct.pack("!4s4sBBH", src_IP, dest_IP, 0, socket.IPPROTO_TCP, len(reply_tcp_header_option))
        checksum = calculate_tcp_checksum(pseudo_hdr + reply_tcp_header_option)

        return reply_tcp_header_option[:16] + struct.pack("H", checksum) + reply_tcp_header_option[18:]
    except Exception as e:
        logging.error(f"Error building OS deception TCP header: {e}")
        return None


def calculate_ip_checksum(data):
    """ Calculates the IP checksum. """
    try:
        packet_sum = sum((data[i] << 8) + data[i + 1] for i in range(0, len(data), 2))
        packet_sum = (packet_sum >> 16) + (packet_sum & 0xffff)
        packet_sum = ~packet_sum & 0xffff
        return packet_sum
    except Exception as e:
        logging.error(f"Error calculating IP checksum: {e}")
        return 0


def calculate_tcp_checksum(packet):
    """ Calculates the TCP checksum. """
    try:
        if len(packet) % 2 != 0:
            packet += b"\0"

        res = sum(array.array("H", packet))
        res = (res >> 16) + (res & 0xffff)
        res += res >> 16

        return (~res) & 0xffff
    except Exception as e:
        logging.error(f"Error calculating TCP checksum: {e}")
        return 0


def byte_to_mac(mac_byte):
    """ Converts a MAC address from bytes to a string format. """
    try:
        return ":".join(f"{b:02x}" for b in mac_byte)
    except Exception as e:
        logging.error(f"Error converting MAC address: {e}")
        return "00:00:00:00:00:00"


def byte_to_ip(ip_byte):
    """ Converts an IP address from bytes to a string format. """
    try:
        return socket.inet_ntoa(ip_byte)
    except Exception as e:
        logging.error(f"Error converting IP address: {e}")
        return "0.0.0.0"
