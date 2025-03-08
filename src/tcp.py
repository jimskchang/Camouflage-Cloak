import socket
import binascii
import struct
import array
import src.settings as settings

class TcpConnect:
    def __init__(self, host: str):
        """
        Initializes a raw socket connection for TCP packet manipulation.
        Reads the MAC address from the NIC settings and binds the socket.
        """
        self.dip = host
        
        try:
            with open(settings.NIC_ADDR_PATH) as f:
                mac = f.readline().strip()
                self.mac = binascii.unhexlify(mac.replace(':', ''))  # Fixed MAC parsing
        except FileNotFoundError:
            raise ValueError(f"Error: NIC address file {settings.NIC_ADDR_PATH} not found.")

        self.sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
        self.sock.bind((settings.NIC, 0))

    def build_tcp_header_from_reply(self, tcp_len: int, seq: int, ack_num: int, src_port: int, dest_port: int, src_IP: bytes, dest_IP: bytes, flags: int) -> bytes:
        """
        Build a TCP header with a correct checksum for reply packets.
        """
        offset = (tcp_len // 4) << 4  # Ensure proper 4-bit shifting
        reply_tcp_header = struct.pack('!HHIIBBHHH', src_port, dest_port, seq, ack_num, offset, flags, 0, 0, 0)
        
        # Construct Pseudo Header for Checksum
        pseudo_hdr = struct.pack('!4s4sBBH', src_IP, dest_IP, 0, socket.IPPROTO_TCP, len(reply_tcp_header))
        checksum = getTCPChecksum(pseudo_hdr + reply_tcp_header)
        
        # Insert the computed checksum
        reply_tcp_header = reply_tcp_header[:16] + struct.pack('!H', checksum) + reply_tcp_header[18:]
        return reply_tcp_header


def getTCPChecksum(packet: bytes) -> int:
    """
    Compute TCP checksum to ensure data integrity in TCP packets.
    """
    if len(packet) % 2 != 0:
        packet += b'\0'
    res = sum(array.array("H", packet))
    res = (res >> 16) + (res & 0xffff)
    res += res >> 16
    return (~res) & 0xffff


def getIPChecksum(packet: bytes) -> int:
    """
    Compute the IP checksum for a given packet header.
    """
    if len(packet) % 2:
        packet += b'\0'  # Ensure even number of bytes
    checksum = sum(struct.unpack("!" + ("H" * (len(packet) // 2)), packet))
    checksum = (checksum >> 16) + (checksum & 0xFFFF)
    checksum = ~checksum & 0xFFFF
    return checksum


def byte2mac(mac_byte: bytes) -> str:
    """
    Convert a MAC address from byte format to human-readable string format.
    """
    return "%02x:%02x:%02x:%02x:%02x:%02x" % struct.unpack("BBBBBB", mac_byte)


def byte2ip(ip_byte: bytes) -> str:
    """
    Convert an IP address from byte format to human-readable string format.
    """
    return socket.inet_ntoa(ip_byte)
