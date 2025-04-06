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

        from src.fingerprint_utils import generateKey

    def get_signature(self, proto_type: str) -> bytes:
        try:
            return generateKey(self, proto_type)
        except Exception as e:
            logging.warning(f"[Packet] Failed to get signature for {proto_type}: {e}")
            return b""

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
                'sender_mac': fields[5],
                'sender_ip': fields[6],
                'recv_mac': fields[7],
                'recv_ip': fields[8],
            }
        except Exception as e:
            logging.error(f"[ARP] Error unpacking: {e}")

    def unpack_ip_header(self) -> None:
        try:
            start = len(self.l2_header)
            ihl = self.packet[start] & 0x0F
            self.l3_header = self.packet[start:start + ihl * 4]
            fields = struct.unpack('!BBHHHBBH4s4s', self.l3_header[:20])
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
                'dest_IP_str': socket.inet_ntoa(fields[9]),
                'options': self.packet[start + 20:start + ihl * 4] if ihl > 5 else b''
            }
        except Exception as e:
            logging.error(f"[IP] Error unpacking: {e}")

    def unpack_tcp_header(self) -> None:
        try:
            start = len(self.l2_header) + (self.l3_field.get('IHL_VERSION', 0) & 0x0F) * 4
            offset = (self.packet[start + 12] >> 4)
            self.l4_header = self.packet[start:start + offset * 4]
            fields = struct.unpack('!HHLLBBHHH', self.l4_header[:20])
            self.l4_field = {
                'src_port': fields[0],
                'dest_port': fields[1],
                'seq': fields[2],
                'ack_num': fields[3],
                'offset': offset * 4,
                'flags': fields[5],
                'reserved': (fields[4] & 0x0E) >> 1,
                'window': self.window_override if self.window_override is not None else fields[6],
                'checksum': fields[7],
                'urgent_ptr': fields[8],
                'kind_seq': [],
                'option_field': {}
            }
            option_data = self.l4_header[20:offset * 4]
            i = 0
            while i < len(option_data):
                kind = option_data[i]
                self.l4_field['kind_seq'].append(kind)
                if kind == 0:
                    break
                elif kind == 1:
                    i += 1
                    continue
                else:
                    length = option_data[i + 1]
                    value = option_data[i + 2:i + length]
                    if kind == 2 and len(value) >= 2:
                        self.l4_field['option_field']['mss'] = struct.unpack('!H', value[:2])[0]
                    elif kind == 3 and len(value) >= 1:
                        self.l4_field['option_field']['ws'] = struct.unpack('!B', value[:1])[0]
                    elif kind == 8 and len(value) >= 8:
                        self.l4_field['option_field']['ts_val'], self.l4_field['option_field']['ts_echo_reply'] = struct.unpack('!II', value[:8])
                    i += length
        except Exception as e:
            logging.error(f"[TCP] Error unpacking: {e}")

    def unpack_udp_header(self) -> None:
        try:
            start = len(self.l2_header) + (self.l3_field.get('IHL_VERSION', 0) & 0x0F) * 4
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

    def unpack_icmp_header(self) -> None:
        try:
            start = len(self.l2_header) + (self.l3_field.get('IHL_VERSION', 0) & 0x0F) * 4
            self.l4_header = self.packet[start:start + settings.ICMP_HEADER_LEN]
            fields = struct.unpack('!BBHHH', self.l4_header)
            self.l4_field = {
                'icmp_type': fields[0],
                'code': fields[1],
                'checksum': fields[2],
                'ID': fields[3],
                'seq': fields[4],
            }
        except Exception as e:
            logging.error(f"[ICMP] Error unpacking: {e}")

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
