# ✅ 修正後的 Packet.py
import logging
import socket
import struct
import array
import src.settings as settings

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

    def unpack(self) -> None:
        try:
            self.unpack_l2_header()
            self.unpack_l3_header(self.l3)
            if self.l4:
                self.unpack_l4_header(self.l4)
        except Exception as e:
            logging.error(f"[Packet] General unpack error: {e}")

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

    def unpack_ip_header(self) -> None:
        try:
            start = len(self.l2_header)
            self.l3_header = self.packet[start:start + settings.IP_HEADER_LEN]
            fields = struct.unpack('!BBHHHBBH4s4s', self.l3_header)
            self.l4 = {1: 'icmp', 6: 'tcp', 17: 'udp'}.get(fields[6], 'others')
            self.l3_field = {
                'IHL_VERSION': fields[0],
                'TYPE_OF_SERVICE': fields[1],
                'total_len': fields[2],
                'pktID': fields[3],
                'FRAGMENT_STATUS': fields[4],
                'ttl': self.ttl_override if self.ttl_override is not None else fields[5],
                'PROTOCOL': fields[6],
                'check_sum_of_hdr': fields[7],
                'src_IP': fields[8],
                'dest_IP': fields[9],
                'src_IP_str': socket.inet_ntoa(fields[8]),
                'dest_IP_str': socket.inet_ntoa(fields[9])
            }
        except Exception as e:
            logging.error(f"[IP] Error unpacking: {e}")

    def unpack_udp_header(self) -> None:
        try:
            start = len(self.l2_header) + settings.IP_HEADER_LEN
            self.l4_header = self.packet[start:start + settings.UDP_HEADER_LEN]
            fields = struct.unpack('!HHHH', self.l4_header)
            self.l4_field = {
                'src_port': fields[0],
                'dest_port': fields[1],
                'length': fields[2],
                'checksum': fields[3],
            }
        except Exception as e:
            logging.error(f"[UDP] Error unpacking: {e}")

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
                'sender_mac': fields[5],
                'sender_ip': fields[6],
                'recv_mac': fields[7],
                'recv_ip': fields[8],
            }
        except Exception as e:
            logging.error(f"[ARP] Error unpacking: {e}")
