import socket
import binascii
import struct
import array
import time
import src.settings as settings  # Ensure src/settings.py exists
from src.utils import calculate_checksum  # Ensure src/utils.py exists


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
        checksum = calculate_checksum(pseudo_hdr + tcp_header) & 0xFFFF  # Ensure 16-bit value

        # Insert checksum into TCP header
        return tcp_header[:16] + struct.pack('H', checksum) + tcp_header[18:]


def getTCPChecksum(src_ip, dest_ip, tcp_header):
    """
    Computes the TCP checksum.
    """
    pseudo_header = struct.pack('!4s4sBBH', src_ip, dest_ip, 0, socket.IPPROTO_TCP, len(tcp_header))
    checksum = calculate_checksum(pseudo_header + tcp_header) & 0xFFFF  # Ensure 16-bit value
    return struct.pack('H', checksum)


def getIPChecksum(ip_header):
    """
    Computes the checksum for an IP header.
    """
    checksum = calculate_checksum(ip_header) & 0xFFFF  # Ensure 16-bit value
    return struct.pack('H', checksum)


def build_tcp_header_with_options(tcp_len, seq, ack_num, src_port, dest_port, src_IP, dest_IP, flags, window, options):
    """
    Builds a TCP header with optional TCP options.
    """
    offset = tcp_len << 4
    tcp_header = struct.pack('!HHIIBBHHH', src_port, dest_port, seq, ack_num, offset, flags, window, 0, 0)
    tcp_header_with_options = tcp_header + options

    # Calculate checksum
    pseudo_hdr = struct.pack('!4s4sBBH', src_IP, dest_IP, 0, socket.IPPROTO_TCP, len(tcp_header_with_options))
    checksum = calculate_checksum(pseudo_hdr + tcp_header_with_options) & 0xFFFF  # Ensure 16-bit value

    return tcp_header_with_options[:16] + struct.pack('H', checksum) + tcp_header_with_options[18:]


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
