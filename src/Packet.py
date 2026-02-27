import logging
import socket
import struct
import array
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
            # 高效unpack：先檢查長度再解析
            if len(self.packet) < 14: return
            self.unpack_l2_header()
            self.unpack_l3_header()
            self.unpack_l4_header()
        except Exception as e:
            logging.debug(f"[Packet] Parsing error: {e}")

    def unpack_l2_header(self) -> None:
        try:
            eth_dMAC, eth_sMAC, eth_type = struct.unpack('!6s6sH', self.packet[:14])
            
            # 使用列表推導式可能更快，但為了可讀性保持現狀
            eth_dMAC_str = ':'.join('%02x' % b for b in eth_dMAC)
            eth_sMAC_str = ':'.join('%02x' % b for b in eth_sMAC)
            
            if eth_type == 0x8100: # VLAN
                if len(self.packet) < 18: return
                vlan_tag = struct.unpack('!H', self.packet[14:16])[0]
                real_eth_type = struct.unpack('!H', self.packet[16:18])[0]
                self.l2_field = {'dMAC': eth_dMAC_str, 'sMAC': eth_sMAC_str, 'protocol': real_eth_type, 'vlan': vlan_tag & 0x0FFF}
                self.l3 = {0x0800: 'ip', 0x0806: 'arp'}.get(real_eth_type, 'others')
                self.l2_header = self.packet[:18]
            else:
                self.l2_field = {'dMAC': eth_dMAC_str, 'sMAC': eth_sMAC_str, 'protocol': eth_type, 'vlan': None}
                self.l3 = {0x0800: 'ip', 0x0806: 'arp'}.get(eth_type, 'others')
                self.l2_header = self.packet[:14]
        except Exception as e:
            logging.error(f"[L2] Error unpacking: {e}")

    def unpack_l3_header(self) -> None:
        if self.l3 == 'ip':
            self.unpack_ip_header()
        elif self.l3 == 'arp':
            self.unpack_arp_header()

    def unpack_l4_header(self) -> None:
        if self.l4 == 'tcp':
            self.unpack_tcp_header()
        elif self.l4 == 'udp':
            self.unpack_udp_header()
        elif self.l4 == 'icmp':
            self.unpack_icmp_header()

    def unpack_arp_header(self) -> None:
        try:
            start = len(self.l2_header)
            self.l3_header = self.packet[start:start + settings.ARP_HEADER_LEN]
            if len(self.l3_header) < settings.ARP_HEADER_LEN: return
            
            fields = struct.unpack('!HHBBH6s4s6s4s', self.l3_header)
            self.l3_field = {
                'hw_type': fields[0],
                'proto_type': fields[1],
                'hw_size': fields[2],
                'proto_size': fields[3],
                'opcode': fields[4],
                'sender_mac': ':'.join('%02x' % b for b in fields[5]),
                'sender_ip': socket.inet_ntoa(fields[6]),
                'recv_mac': ':'.join('%02x' % b for b in fields[7]),
                'recv_ip': socket.inet_ntoa(fields[8]),
                'src_IP_str': socket.inet_ntoa(fields[6]),
                'dest_IP_str': socket.inet_ntoa(fields[8])
            }
        except Exception as e:
            logging.error(f"[ARP] Error unpacking: {e}")

    def unpack_ip_header(self) -> None:
        try:
            start = len(self.l2_header)
            if len(self.packet) < start + 20: return
            
            # 檢查 IHL (Header Length) 是否合理
            ihl = self.packet[start] & 0x0F
            if ihl < 5: return 
            
            self.l3_header = self.packet[start:start + ihl * 4]
            fields = struct.unpack('!BBHHHBBH4s4s', self.l3_header[:20])
            
            self.l4 = {1: 'icmp', 6: 'tcp', 17: 'udp'}.get(fields[6], 'others')
            
            self.l3_field = {
                'IHL_VERSION': fields[0],
                'ttl': self.ttl_override if self.ttl_override is not None else fields[5],
                'PROTOCOL': fields[6],
                'src_IP_str': socket.inet_ntoa(fields[8]),
                'dest_IP_str': socket.inet_ntoa(fields[9]),
                'options': self.l3_header[20:]
            }
        except Exception as e:
            logging.error(f"[IP] Error unpacking: {e}")

    def unpack_tcp_header(self) -> None:
        try:
            start = len(self.l2_header) + (self.l3_field.get('IHL_VERSION', 0) & 0x0F) * 4
            if len(self.packet) < start + 20: return
            
            offset = (self.packet[start + 12] >> 4)
            self.l4_header = self.packet[start:start + offset * 4]
            fields = struct.unpack('!HHLLBBHHH', self.l4_header[:20])
            
            self.l4_field = {
                'src_port': fields[0],
                'dest_port': fields[1],
                'seq': fields[2],
                'ack_num': fields[3],
                'flags': fields[5],
                'window': self.window_override if self.window_override is not None else fields[6],
                'option_field': {}
            }
            # 解析 TCP Options
            option_data = self.l4_header[20:]
            i = 0
            while i < len(option_data):
                kind = option_data[i]
                if kind == 0: break
                if kind == 1:
                    i += 1
                    continue
                if i + 1 >= len(option_data): break
                length = option_data[i + 1]
                if i + length > len(option_data): break
                
                value = option_data[i + 2:i + length]
                if kind == 2 and len(value) >= 2:
                    self.l4_field['option_field']['mss'] = struct.unpack('!H', value[:2])[0]
                elif kind == 3 and len(value) >= 1:
                    self.l4_field['option_field']['ws'] = struct.unpack('!B', value[:1])[0]
                elif kind == 8 and len(value) >= 8:
                    self.l4_field['option_field']['ts_val'], self.l4_field['option_field']['ts_echo_reply'] = struct.unpack('!II', value[:8])
                i += length
        except Exception as e:
            logging.debug(f"[TCP] Error unpacking: {e}")

    # ... (unpack_udp_header 和 unpack_icmp_header 結構類似，加上長度檢查即可)

    @staticmethod
    def getTCPChecksum(packet: bytes) -> int:
        # 正確的校驗和計算，通常需要偽標頭(Pseudo-header)參與，
        # 此處僅為 TCP Segment 的校驗和計算
        if len(packet) % 2 != 0:
            packet += b'\0'
        res = sum(array.array("H", packet))
        res = (res >> 16) + (res & 0xFFFF)
        res += res >> 16
        return (~res) & 0xFFFF
