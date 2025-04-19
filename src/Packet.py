# --- Packet.py (updated for ARP consistency) ---

import logging
import socket
import struct
import array
import hashlib
import src.settings as settings
from src.fingerprint_gen import generateKey

class Packet:
    def __init__(self, packet=b'', proc=None, l2_field=None, l3_field=None, l4_field=None, data='', ttl=None, window=None):
        self.packet = packet
        self.l3 = proc if proc in settings.L3_PROC else 'ip'
        self.l4 = proc if proc in settings.L4_PROC else ''
        self.l2_header = b''
        self.l3_header = b''
        self.l4_header = b''
        self.l2_field = l2_field or {}
        self.l3_field = l3_field or {}
        self.l4_field = l4_field or {}
        self.data = data
        self.interface = None

        self.ttl_override = ttl
        self.window_override = window

    def get_signature(self, proto_type: str) -> bytes:
        try:
            return generateKey(self, proto_type)
        except Exception as e:
            logging.warning(f"[Packet] Failed to get signature for {proto_type}: {e}")
            return b''

    def unpack(self) -> None:
        try:
            self.setL2Header(self.packet)
            self.setL3Header(self.packet)
            self.setL4Header(self.packet)
        except Exception as e:
            logging.error(f"[Packet] General unpack error: {e}")

    def setL2Header(self, raw_packet: bytes):
        self.packet = raw_packet
        self.unpack_l2_header()

    def setL3Header(self, raw_packet: bytes):
        self.packet = raw_packet
        self.unpack_l3_header(self.l3)

    def setL4Header(self, raw_packet: bytes):
        self.packet = raw_packet
        self.unpack_l4_header(self.l4)

    def unpack_l2_header(self) -> None:
        if len(self.packet) < settings.ETH_HEADER_LEN:
            logging.error("[L2] Packet too short for Ethernet header.")
            return
        try:
            eth_dMAC, eth_sMAC, eth_type = struct.unpack('!6s6sH', self.packet[:14])

            if eth_type == 0x8100 and len(self.packet) >= 18:
                vlan_tag = struct.unpack('!H', self.packet[14:16])[0]
                real_eth_type = struct.unpack('!H', self.packet[16:18])[0]
                vlan_id = vlan_tag & 0x0FFF

                self.l2_field = {
                    'dMAC': eth_dMAC,
                    'sMAC': eth_sMAC,
                    'protocol': real_eth_type,
                    'vlan': vlan_id
                }
                self.l3 = {0x0800: 'ip', 0x0806: 'arp'}.get(real_eth_type, 'others')
                self.l2_header = self.packet[:18]
            else:
                self.l2_field = {
                    'dMAC': eth_dMAC,
                    'sMAC': eth_sMAC,
                    'protocol': eth_type,
                    'vlan': None
                }
                self.l3 = {0x0800: 'ip', 0x0806: 'arp'}.get(eth_type, 'others')
                self.l2_header = self.packet[:14]
        except Exception as e:
            logging.error(f"[L2] Error unpacking Ethernet/VLAN: {e}")

    def unpack_l3_header(self, l3: str) -> None:
        if l3 == 'ip':
            self.unpack_ip_header()
        elif l3 == 'arp':
            self.unpack_arp_header()

    def unpack_l4_header(self, l4: str) -> None:
        if l4 == 'tcp':
            self.unpack_tcp_header()
        elif l4 == 'udp':
            self.unpack_udp_header()
        elif l4 == 'icmp':
            self.unpack_icmp_header()

    def unpack_arp_header(self) -> None:
        try:
            start = len(self.l2_header)
            self.l3_header = self.packet[start:start + settings.ARP_HEADER_LEN]
            fields = struct.unpack('!HHBBH6s4s6s4s', self.l3_header)
            self.l3_field = {
                'hw_type': fields[0],
                'proto_type': fields[1],
                'hw_size': fields[2],
                'proto_size': fields[3],
                'opcode': fields[4],
                'sender_mac': fields[5].hex(':'),
                'sender_ip': socket.inet_ntoa(fields[6]),
                'recv_mac': fields[7].hex(':'),
                'recv_ip': socket.inet_ntoa(fields[8]),
                'src_IP_str': socket.inet_ntoa(fields[6]),
                'dest_IP_str': socket.inet_ntoa(fields[8])
            }
        except Exception as e:
            logging.error(f"[ARP] Error unpacking: {e}")

    # (unchanged IP, TCP, UDP, ICMP header parsing methods)

    @staticmethod
    def getTCPChecksum(packet: bytes) -> int:
        if len(packet) % 2 != 0:
            packet += b'\0'
        res = sum(array.array("H", packet))
        res = (res >> 16) + (res & 0xFFFF)
        res += res >> 16
        return (~res) & 0xFFFF

    @staticmethod
    def getUDPChecksum(data: bytes) -> int:
        checksum = 0
        if len(data) % 2:
            data += b'\0'
        for i in range(0, len(data), 2):
            checksum += (data[i] << 8) + data[i+1]
        checksum = (checksum >> 16) + (checksum & 0xFFFF)
        return ~checksum & 0xFFFF
