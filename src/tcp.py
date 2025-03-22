import socket
import binascii
import struct
import array
import logging
import src.settings as settings

class TcpConnect:
    def __init__(self, host: str):
        """
        Initializes a raw socket connection for TCP packet manipulation.
        """
        self.dip = host
        self.mac = settings.MAC

        try:
            self.sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
            self.sock.bind((settings.NIC_PROBE, 0))
            logging.info(f"✅ Raw socket bound to {settings.NIC_PROBE} for deception")
        except PermissionError:
            logging.error("Root privileges are required to create raw sockets. Run with sudo.")
            raise
        except socket.error as e:
            logging.error(f"Failed to create raw socket: {e}")
            raise

    def build_tcp_header_from_reply(
        self, tcp_len: int, seq: int, ack_num: int, 
        src_port: int, dest_port: int, src_IP: bytes, 
        dest_IP: bytes, flags: int
    ) -> bytes:
        """
        Build a TCP header with a correct checksum for reply packets.
        """
        try:
            offset = (tcp_len // 4) << 4  # Ensure proper 4-bit shifting
            reply_tcp_header = struct.pack('!HHIIBBHHH', src_port, dest_port, seq, ack_num, offset, flags, 0, 0, 0)

            # Construct Pseudo Header for Checksum
            pseudo_hdr = struct.pack('!4s4sBBH', src_IP, dest_IP, 0, socket.IPPROTO_TCP, len(reply_tcp_header))
            checksum = getTCPChecksum(pseudo_hdr + reply_tcp_header)

            # Insert the computed checksum
            reply_tcp_header = reply_tcp_header[:16] + struct.pack('!H', checksum) + reply_tcp_header[18:]
            return reply_tcp_header
        except struct.error as e:
            logging.error(f"Error building TCP header: {e}")
            return b''

def getTCPChecksum(packet: bytes) -> int:
    if len(packet) % 2 != 0:
        packet += b'\0'
    res = sum(array.array("H", packet))
    res = (res >> 16) + (res & 0xffff)
    res += res >> 16
    return (~res) & 0xffff

def getIPChecksum(packet: bytes) -> int:
    if len(packet) % 2:
        packet += b'\0'
    checksum = sum(struct.unpack("!" + "H" * (len(packet) // 2), packet))
    checksum = (checksum >> 16) + (checksum & 0xFFFF)
    checksum = ~checksum & 0xFFFF
    return checksum

def byte2mac(mac_byte: bytes) -> str:
    if len(mac_byte) != 6:
        logging.error("Invalid MAC address length.")
        return "00:00:00:00:00:00"
    return ":".join(f"{b:02x}" for b in mac_byte)

def byte2ip(ip_byte: bytes) -> str:
    try:
        return socket.inet_ntoa(ip_byte)
    except socket.error as e:
        logging.error(f"Invalid IP address conversion: {e}")
        return "0.0.0.0"
