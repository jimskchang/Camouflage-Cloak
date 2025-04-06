import socket
import struct
import array
import binascii
import logging
import os
import random
import time
from scapy.all import Ether, IP, TCP

import src.settings as settings

class TcpConnect:
    def __init__(self, host: str, nic: str = None, drop_chance: float = 0.0, delay_range=(0, 0)):
        self.dip = host
        self.nic = nic or settings.NIC_PROBE
        self.drop_chance = drop_chance
        self.delay_range = delay_range  # in seconds, e.g. (0.01, 0.05)

        if not check_nic_exists_and_up(self.nic):
            raise RuntimeError(f"❌ NIC {self.nic} does not exist or is not UP.")

        self.mac = self._get_mac_bytes(self.nic)

        try:
            self.sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
            self.sock.bind((self.nic, 0))
            logging.info(f"✅ Raw socket bound to {self.nic}")
        except PermissionError:
            raise RuntimeError("❌ Root privileges required for raw socket.")
        except socket.error as e:
            raise RuntimeError(f"❌ Socket error: {e}")

    def _get_mac_bytes(self, nic):
        try:
            with open(f"/sys/class/net/{nic}/address", "r") as f:
                mac = f.read().strip()
                logging.info(f"✅ MAC of {nic}: {mac}")
                return binascii.unhexlify(mac.replace(':', ''))
        except Exception as e:
            raise RuntimeError(f"❌ Failed to read MAC for {nic}: {e}")

    def build_tcp_header_from_reply(self, tcp_len, seq, ack_num, src_port, dest_port, src_ip, dest_ip, flags):
        try:
            offset = (tcp_len // 4) << 4
            tcp_header = struct.pack("!HHIIBBHHH",
                                     src_port, dest_port, seq, ack_num,
                                     offset, flags, 0, 0, 0)

            pseudo_hdr = struct.pack("!4s4sBBH", src_ip, dest_ip, 0, socket.IPPROTO_TCP, len(tcp_header))
            checksum = getTCPChecksum(pseudo_hdr + tcp_header)
            tcp_header = tcp_header[:16] + struct.pack("!H", checksum) + tcp_header[18:]
            return tcp_header
        except Exception as e:
            logging.error(f"❌ Error building TCP header: {e}")
            return b''

    def build_tcp_rst(self, pkt, flags="R", seq=None, ack=None) -> bytes:
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
                flags=flags,
                seq=seq if seq is not None else pkt.l4_field.get("ack_num", 0),
                ack=ack if ack is not None else 0,
                window=settings.FALLBACK_WINDOW
            )
            return bytes(ether / ip / tcp)
        except Exception as e:
            logging.error(f"❌ Failed to build TCP {flags}: {e}")
            return b''

    def build_tcp_response(self, pkt, flags="SA", ts=False, ts_echo=0, seq=None) -> bytes:
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
                flags=flags,
                seq=seq if seq else random.randint(0, 0xFFFFFFFF),
                ack=pkt.l4_field.get("seq", 0) + 1,
                window=settings.FALLBACK_WINDOW
            )

            options = [("MSS", 1460)]
            if ts:
                tsval = int(time.time() * 1000) & 0xFFFFFFFF
                options += [("NOP", None), ("NOP", None), ("Timestamp", (tsval, ts_echo))]
            options += [("SAckOK", b''), ("WScale", 7)]
            tcp.options = options

            return bytes(ether / ip / tcp)
        except Exception as e:
            logging.error(f"❌ Failed to build TCP response: {e}")
            return b''

    def send_packet(self, ether_pkt: bytes):
        if self.drop_chance > 0 and random.random() < self.drop_chance:
            logging.warning("🚫 Simulated packet drop.")
            return

        delay = random.uniform(*self.delay_range)
        if delay > 0:
            time.sleep(delay)

        try:
            self.sock.send(ether_pkt)
            logging.debug("📤 Sent raw Ethernet packet.")
        except Exception as e:
            logging.error(f"❌ Failed to send raw packet: {e}")

# --- Utility Functions ---

def check_nic_exists_and_up(nic: str) -> bool:
    path = f"/sys/class/net/{nic}/operstate"
    try:
        with open(path, "r") as f:
            return f.read().strip() == "up"
    except Exception:
        return False

def getTCPChecksum(packet: bytes) -> int:
    if len(packet) % 2:
        packet += b'\0'
    res = sum(array.array("H", packet))
    res = (res >> 16) + (res & 0xFFFF)
    res += res >> 16
    return (~res) & 0xFFFF

def getIPChecksum(packet: bytes) -> int:
    if len(packet) % 2:
        packet += b'\0'
    checksum = sum(struct.unpack("!" + "H" * (len(packet) // 2), packet))
    checksum = (checksum >> 16) + (checksum & 0xFFFF)
    return ~checksum & 0xFFFF

def byte2mac(mac_byte: bytes) -> str:
    return ":".join(f"{b:02x}" for b in mac_byte) if len(mac_byte) == 6 else "00:00:00:00:00:00"

def byte2ip(ip_byte: bytes) -> str:
    try:
        return socket.inet_ntoa(ip_byte)
    except Exception:
        return "0.0.0.0"
