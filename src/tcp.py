# --- Final Corrected tcp.py ---

import socket
import binascii
import struct
import array
import logging
import src.settings as settings

class TcpConnect:
    def __init__(self, host: str):
        self.dip = host
        try:
            self.mac = binascii.unhexlify(settings.MAC.replace(':', ''))
        except Exception as e:
            raise RuntimeError(f"Unexpected error retrieving MAC address: {e}")

        try:
            self.sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
            self.sock.bind((settings.NIC_TARGET, 0))
        except PermissionError:
            logging.error("Root privileges required for raw sockets. Use sudo.")
            raise
        except socket.error as e:
            logging.error(f"Socket creation error: {e}")
            raise

    def build_tcp_header_from_reply(
        self, tcp_len: int, seq: int, ack_num: int,
        src_port: int, dest_port: int, src_IP: bytes,
        dest_IP: bytes, flags: int
    ) -> bytes:
        try:
            offset = (tcp_len // 4) << 4
            header = struct.pack('!HHIIBBHHH', src_port, dest_port, seq, ack_num, offset, flags, 0, 0, 0)
            pseudo = struct.pack('!4s4sBBH', src_IP, dest_IP, 0, socket.IPPROTO_TCP, len(header))
            checksum = getTCPChecksum(pseudo + header)
            return header[:16] + struct.pack('!H', checksum) + header[18:]
        except struct.error as e:
            logging.error(f"TCP header error: {e}")
            return b''

def getTCPChecksum(packet: bytes) -> int:
    if len(packet) % 2:
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
    return ~checksum & 0xFFFF

def byte2mac(mac_byte: bytes) -> str:
    if len(mac_byte) != 6:
        logging.error("Invalid MAC length")
        return "00:00:00:00:00:00"
    return ":".join(f"{b:02x}" for b in mac_byte)

def byte2ip(ip_byte: bytes) -> str:
    try:
        return socket.inet_ntoa(ip_byte)
    except socket.error as e:
        logging.error(f"Invalid IP: {e}")
        return "0.0.0.0"
