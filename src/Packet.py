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
            if len(self.packet) < 14: 
                return
            
            # Use strict boolean gatekeeping to stop structural cascading drops
            if not self.unpack_l2_header(): 
                return
            if not self.unpack_l3_header(): 
                return
            self.unpack_l4_header()
            
        except Exception as e:
            logging.debug(f"[Packet] Parsing error: {e}")

    def unpack_l2_header(self) -> bool:
        try:
            eth_dMAC, eth_sMAC, eth_type = struct.unpack('!6s6sH', self.packet[:14])
            eth_dMAC_str = ':'.join('%02x' % b for b in eth_dMAC)
            eth_sMAC_str = ':'.join('%02x' % b for b in eth_sMAC)
            
            if eth_type == 0x8100: # VLAN Tagged Frame
                if len(self.packet) < 18: 
                    return False
                vlan_tag = struct.unpack('!H', self.packet[14:16])[0]
                real_eth_type = struct.unpack('!H', self.packet[16:18])[0]
                self.l2_field = {'dMAC': eth_dMAC_str, 'sMAC': eth_sMAC_str, 'protocol': real_eth_type, 'vlan': vlan_tag & 0x0FFF}
                self.l3 = {0x0800: 'ip', 0x0806: 'arp'}.get(real_eth_type, 'others')
                self.l2_header = self.packet[:18]
            else:
                self.l2_field = {'dMAC': eth_dMAC_str, 'sMAC': eth_sMAC_str, 'protocol': eth_type, 'vlan': None}
                self.l3 = {0x0800: 'ip', 0x0806: 'arp'}.get(eth_type, 'others')
                self.l2_header = self.packet[:14]
            return True
        except Exception as e:
            logging.error(f"[L2] Error unpacking: {e}")
            return False

    def unpack_l3_header(self) -> bool:
        if self.l3 == 'ip':
            return self.unpack_ip_header()
        elif self.l3 == 'arp':
            return self.unpack_arp_header()
        return False

    def unpack_arp_header(self) -> bool:
        try:
            start = len(self.l2_header)
            if len(self.packet) < start + settings.ARP_HEADER_LEN: 
                return False
                
            self.l3_header = self.packet[start:start + settings.ARP_HEADER_LEN]
            fields = struct.unpack('!HHBBH6s4s6s4s', self.l3_header)
            self.l3_field = {
                'hw_type': fields[0], 'proto_type': fields[1],
                'hw_size': fields[2], 'proto_size': fields[3], 'opcode': fields[4],
                'sender_mac': ':'.join('%02x' % b for b in fields[5]),
                'sender_ip': socket.inet_ntoa(fields[6]),
                'recv_mac': ':'.join('%02x' % b for b in fields[7]),
                'recv_ip': socket.inet_ntoa(fields[8]),
                'src_IP_str': socket.inet_ntoa(fields[6]),
                'dest_IP_str': socket.inet_ntoa(fields[8])
            }
            return True
        except Exception as e:
            logging.error(f"[ARP] Error unpacking: {e}")
            return False

    def unpack_ip_header(self) -> bool:
        try:
            start = len(self.l2_header)
            if len(self.packet) < start + 20: 
                return False
            
            ihl = self.packet[start] & 0x0F
            if ihl < 5 or len(self.packet) < start + (ihl * 4): 
                return False 
            
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
            return True
        except Exception as e:
            logging.error(f"[IP] Error unpacking: {e}")
            return False

    def unpack_tcp_header(self) -> None:
        try:
            if not self.l3_field: 
                return # Safe exit if IP layer validation dropped out
                
            start = len(self.l2_header) + (self.l3_field.get('IHL_VERSION', 0) & 0x0F) * 4
            if len(self.packet) < start + 20: 
                return
            
            offset = (self.packet[start + 12] >> 4)
            if len(self.packet) < start + (offset * 4): 
                return
                
            self.l4_header = self.packet[start:start + offset * 4]
            fields = struct.unpack('!HHLLBBHHH', self.l4_header[:20])
            
            self.l4_field = {
                'src_port': fields[0], 'dest_port': fields[1],
                'seq': fields[2], 'ack_num': fields[3], 'flags': fields[5],
                'window': self.window_override if self.window_override is not None else fields[6],
                'option_field': {}
            }
            
            # --- Robust TCP Options Processing ---
            option_data = self.l4_header[20:]
            i = 0
            while i < len(option_data):
                kind = option_data[i]
                if kind == 0: 
                    break
                if kind == 1:
                    i += 1
                    continue
                if i + 1 >= len(option_data): 
                    break
                    
                length = option_data[i + 1]
                if length < 2 or (i + length) > len(option_data): 
                    break # Break out of bad lengths to avoid stuck loops
                
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

    @staticmethod
    def getTCPChecksum(packet: bytes) -> int:
        if len(packet) % 2 != 0:
            packet += b'\0'
        res = sum(array.array("H", packet))
        res = (res >> 16) + (res & 0xFFFF)
        res += res >> 16
        return (~res) & 0xFFFF
