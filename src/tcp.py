# src/tcp.py

import socket
import struct
import array
import binascii
import logging
import os
import random
import time
from scapy.all import Ether, IP, TCP, UDP, IPv6

import src.settings as settings

logger = logging.getLogger(__name__)

class TcpConnect:
    def __init__(self, host: str, nic: str = None, drop_chance: float = 0.0, delay_range=(0, 0)):
        self.dip = host
        self.nic = nic or settings.NIC_PROBE
        self.drop_chance = drop_chance
        self.delay_range = delay_range

        if not check_nic_exists_and_up(self.nic):
            raise RuntimeError(f"❌ NIC {self.nic} does not exist or is not UP.")

        self.mac = self._get_mac_bytes(self.nic)

        try:
            self.sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
            self.sock.bind((self.nic, 0))
            logger.info(f"✅ Raw socket bound to {self.nic}")
        except PermissionError:
            raise RuntimeError("❌ Root privileges required for raw socket.")
        except socket.error as e:
            raise RuntimeError(f"❌ Socket error: {e}")

    def _get_mac_bytes(self, nic):
        try:
            with open(f"/sys/class/net/{nic}/address", "r") as f:
                mac = f.read().strip()
                logger.info(f"✅ MAC of {nic}: {mac}")
                return binascii.unhexlify(mac.replace(':', ''))
        except Exception as e:
            raise RuntimeError(f"❌ Failed to read MAC for {nic}: {e}")

    def build_tcp_rst(self, pkt, flags="R", seq=None, ack=None, vlan=None, ipv6=False) -> bytes:
        try:
            ether = Ether(src=pkt.l2_field['dMAC'], dst=pkt.l2_field['sMAC'])

            if vlan:
                ether.type = 0x8100
                ether = ether / struct.pack("!HH", 0x0000, vlan)

            ip_layer = IPv6(src=pkt.l3_field['dest_IP_str'], dst=pkt.l3_field['src_IP_str']) if ipv6 else IP(
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

            return bytes(ether / ip_layer / tcp)
        except Exception as e:
            logger.error(f"❌ Failed to build TCP {flags}: {e}")
            return b''

    def build_tcp_ack(self, pkt, seq=None, ack=None) -> bytes:
        try:
            ether = Ether(src=pkt.l2_field['dMAC'], dst=pkt.l2_field['sMAC'])
            ip = IP(src=pkt.l3_field['dest_IP_str'], dst=pkt.l3_field['src_IP_str'], ttl=64)
            tcp = TCP(
                sport=pkt.l4_field['dest_port'],
                dport=pkt.l4_field['src_port'],
                flags="A",
                seq=seq or random.randint(0, 4294967295),
                ack=ack or pkt.l4_field.get("seq", 0) + 1,
                window=settings.FALLBACK_WINDOW
            )
            return bytes(ether / ip / tcp)
        except Exception as e:
            logger.error(f"❌ Failed to build TCP ACK: {e}")
            return b''

    def send_packet(self, ether_pkt: bytes):
        if self.drop_chance > 0 and random.random() < self.drop_chance:
            logger.warning("🚫 Simulated packet drop.")
            return

        delay = random.uniform(*self.delay_range)
        if delay > 0:
            time.sleep(delay)

        try:
            self.sock.send(ether_pkt)
            logger.debug(f"📤 Sent packet preview: {ether_pkt[:64].hex()}...")
        except Exception as e:
            logger.error(f"❌ Failed to send raw packet: {e}")

    def extract_ja3_fingerprint(self, pkt):
        try:
            if b"\x16\x03" in pkt.packet and b"\x01" in pkt.packet[5:6]:
                client_hello = pkt.packet[pkt.packet.find(b"\x16\x03"):]
                return "stub_ja3_hash"
        except Exception as e:
            logger.warning(f"⚠️ JA3 parsing error: {e}")
        return None

# --- Utility Functions ---

def check_nic_exists_and_up(nic: str) -> bool:
    try:
        with open(f"/sys/class/net/{nic}/operstate", "r") as f:
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
