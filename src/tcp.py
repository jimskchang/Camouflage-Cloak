import socket
import binascii
import struct
import array
import logging
import src.settings as settings

class TcpConnect:
    def __init__(self, host: str, nic: str = None):
        """
        Initializes a raw socket connection for TCP packet manipulation.
        """
        self.dip = host
        self.nic = nic or settings.NIC_PROBE  # Default to NIC_PROBE if not provided

        mac_path = f"/sys/class/net/{self.nic}/address"
        try:
            with open(mac_path, 'r') as f:
                mac = f.readline().strip()
                if not mac:
                    raise ValueError(f"MAC address file {mac_path} is empty.")
                self.mac = binascii.unhexlify(mac.replace(':', ''))  # Convert to binary
        except FileNotFoundError:
            raise ValueError(f"❌ Error: MAC address file not found for NIC: {self.nic}")
        except Exception as e:
            raise RuntimeError(f"❌ Unexpected error reading MAC address: {e}")

        try:
            self.sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
            self.sock.bind((self.nic, 0))
            logging.info(f"✅ Bound raw socket to NIC: {self.nic}")
        except PermissionError:
            logging.error("❌ Root privileges are required to create raw sockets.")
            raise
        except socket.error as e:
            logging.error(f"❌ Failed to create or bind socket: {e}")
            raise

    def build_tcp_header_from_reply(
        self, tcp_len: int, seq: int, ack_num: int, 
        src_port: int, dest_port: int, src_IP: bytes, 
        dest_IP: bytes, flags: int
    ) -> bytes:
        """
        Builds a TCP header with proper checksum for spoofed replies.
        """
        try:
            offset = (tcp_len // 4) << 4  # TCP header offset (data offset field)
            reply_tcp_header = struct.pack('!HHIIBBHHH',
                                           src_port, dest_port, seq, ack_num,
                                           offset, flags, 0, 0, 0)

            pseudo_hdr = struct.pack('!4s4sBBH', src_IP, dest_IP, 0, socket.IPPROTO_TCP, len(reply_tcp_header))
            checksum = getTCPChecksum(pseudo_hdr + reply_tcp_header)

            reply_tcp_header = reply_tcp_header[:16] + struct.pack('!H', checksum) + reply_tcp_header[18:]
            return reply_tcp_header
        except struct.error as e:
            logging.error(f"❌ TCP Header build error: {e}")
            return b''


# --- Utility Functions ---

def getTCPChecksum(packet: bytes) -> int:
    """Computes TCP checksum."""
    if len(packet) % 2 != 0:
        packet += b'\0'

    res = sum(array.array("H", packet))
    res = (res >> 16) + (res & 0xffff)
    res += res >> 16
    return (~res) & 0xffff


def getIPChecksum(packet: bytes) -> int:
    """Computes IP header checksum."""
    if len(packet) % 2:
        packet += b'\0'

    checksum = sum(struct.unpack("!" + "H" * (len(packet) // 2), packet))
    checksum = (checksum >> 16) + (checksum & 0xFFFF)
    checksum = ~checksum & 0xFFFF
    return checksum


def byte2mac(mac_byte: bytes) -> str:
    """Converts MAC in bytes to readable MAC string."""
    if len(mac_byte) != 6:
        logging.error("Invalid MAC length.")
        return "00:00:00:00:00:00"
    return ":".join(f"{b:02x}" for b in mac_byte)


def byte2ip(ip_byte: bytes) -> str:
    """Converts IP in bytes to dotted format."""
    try:
        return socket.inet_ntoa(ip_byte)
    except socket.error as e:
        logging.error(f"Invalid IP bytes: {e}")
        return "0.0.0.0"
