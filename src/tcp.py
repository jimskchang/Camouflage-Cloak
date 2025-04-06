import socket
import binascii
import struct
import array
import logging
import os
from scapy.all import Ether, IP, TCP

import src.settings as settings


class TcpConnect:
    def __init__(self, host: str, nic: str = None):
        """
        Initializes a raw socket connection for TCP packet manipulation.
        """
        self.dip = host
        self.nic = nic or settings.NIC_PROBE  # Default to NIC_PROBE

        if not check_nic_exists_and_up(self.nic):
            raise RuntimeError(f"❌ NIC {self.nic} does not exist or is not UP.")

        mac_path = f"/sys/class/net/{self.nic}/address"
        try:
            with open(mac_path, 'r') as f:
                mac = f.readline().strip()
                if not mac:
                    raise ValueError(f"MAC address file {mac_path} is empty.")
                self.mac = binascii.unhexlify(mac.replace(':', ''))  # Convert to binary
                logging.info(f"✅ Using MAC address for {self.nic}: {mac}")
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
            offset = (tcp_len // 4) << 4
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

    def send_packet(self, ether_pkt: bytes):
        """
        Sends a fully formed Ethernet packet via raw socket.
        """
        try:
            self.sock.send(ether_pkt)
            logging.debug("📤 Sent raw Ethernet packet.")
        except Exception as e:
            logging.error(f"❌ Failed to send raw packet: {e}")

    def build_tcp_rst(self, pkt) -> bytes:
        """
        Build a TCP RST packet from a captured Packet object.
        """
        try:
            ether = Ether(src=pkt.l2_field['dMAC'], dst=pkt.l2_field['sMAC'])
            ip = IP(
                src=pkt.l3_field['dest_IP_str'],
                dst=pkt.l3_field['src_IP_str'],
                ttl=64,
                id=random.randint(0, 65535)
            )
            tcp = TCP(
                sport=pkt.l4_field['dest_port'],
                dport=pkt.l4_field['src_port'],
                flags="R",
                seq=pkt.l4_field.get('ack_num', 0)
            )
            return bytes(ether / ip / tcp)
        except Exception as e:
            logging.error(f"❌ Failed to build TCP RST: {e}")
            return b''


# --- Utility Functions ---

def check_nic_exists_and_up(nic: str) -> bool:
    """Check if a NIC exists and is up."""
    nic_path = f"/sys/class/net/{nic}"
    operstate_path = os.path.join(nic_path, "operstate")
    try:
        with open(operstate_path, 'r') as f:
            status = f.read().strip()
        return status == 'up'
    except Exception as e:
        logging.error(f"❌ Error checking NIC status: {e}")
        return False


def getTCPChecksum(packet: bytes) -> int:
    """Computes TCP checksum from pseudo-header + TCP header."""
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
    return ~checksum & 0xFFFF


def byte2mac(mac_byte: bytes) -> str:
    """Convert MAC bytes to colon-separated string."""
    if len(mac_byte) != 6:
        logging.error("Invalid MAC length.")
        return "00:00:00:00:00:00"
    return ":".join(f"{b:02x}" for b in mac_byte)


def byte2ip(ip_byte: bytes) -> str:
    """Convert IP bytes to dotted-decimal string."""
    try:
        return socket.inet_ntoa(ip_byte)
    except socket.error as e:
        logging.error(f"❌ Invalid IP bytes: {e}")
        return "0.0.0.0"
