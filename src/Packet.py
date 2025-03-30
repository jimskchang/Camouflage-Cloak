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

    def unpack_tcp_header(self) -> None:
        try:
            start = len(self.l2_header) + settings.IP_HEADER_LEN
            self.l4_header = self.packet[start:start + settings.TCP_HEADER_LEN]
            fields = struct.unpack('!HHLLBBHHH', self.l4_header)
            offset = (fields[4] >> 4) * 4
            flags = fields[5]
            self.l4_field = {
                'src_port': fields[0],
                'dest_port': fields[1],
                'seq': fields[2],
                'ack_num': fields[3],
                'offset': offset,
                'flags': flags,
                'window': self.window_override if self.window_override is not None else fields[6],
                'checksum': fields[7],
                'urgent_ptr': fields[8],
                'flag_str': self.decode_tcp_flags(flags),
                'option_field': {}
            }

            options_raw = self.packet[start + settings.TCP_HEADER_LEN:start + offset]
            i = 0
            while i < len(options_raw):
                kind = options_raw[i]
                if kind == 0:
                    break
                elif kind == 1:
                    i += 1
                    continue
                else:
                    if i + 1 >= len(options_raw): break
                    length = options_raw[i + 1]
                    value = options_raw[i + 2:i + length]
                    if kind == 2 and len(value) >= 2:
                        self.l4_field['option_field']['mss'] = struct.unpack('!H', value[:2])[0]
                    elif kind == 3 and len(value) >= 1:
                        self.l4_field['option_field']['ws'] = struct.unpack('!B', value[:1])[0]
                    elif kind == 8 and len(value) >= 8:
                        self.l4_field['option_field']['ts_val'], self.l4_field['option_field']['ts_echo_reply'] = struct.unpack('!II', value[:8])
                    i += length
        except Exception as e:
            logging.error(f"[TCP] Error unpacking: {e}")

    def decode_tcp_flags(self, flags: int) -> str:
        names = ['FIN', 'SYN', 'RST', 'PSH', 'ACK', 'URG', 'ECE', 'CWR']
        bits = bin(flags)[2:].zfill(8)[-8:]
        return ','.join(name for bit, name in zip(reversed(bits), names) if bit == '1')

    def pack(self) -> None:
        try:
            src_ip = self.l3_field.get('src_IP', b'\x00\x00\x00\x00')
            dst_ip = self.l3_field.get('dest_IP', b'\x00\x00\x00\x00')
            ttl = self.l3_field.get('ttl', 64)
            tos = self.l3_field.get('TYPE_OF_SERVICE', 0)
            proto = self.l3_field.get('PROTOCOL', 6)
            window = self.l4_field.get('window', 8192)

            # TCP
            options = b''
            opt = self.l4_field.get('option_field', {})
            if 'mss' in opt:
                options += struct.pack('!BBH', 2, 4, opt['mss'])
            if 'ws' in opt:
                options += struct.pack('!BBB', 3, 3, opt['ws'])
            if 'ts_val' in opt and 'ts_echo_reply' in opt:
                options += struct.pack('!BBII', 8, 10, opt['ts_val'], opt['ts_echo_reply'])

            while len(options) % 4 != 0:
                options += b'\x00'

            offset = 5 + len(options) // 4
            tcp_header = struct.pack('!HHLLBBHHH',
                self.l4_field['src_port'],
                self.l4_field['dest_port'],
                self.l4_field['seq'],
                self.l4_field['ack_num'],
                offset << 4,
                self.l4_field.get('flags', 0x12),
                window,
                0,
                self.l4_field.get('urgent_ptr', 0)
            )

            pseudo = struct.pack('!4s4sBBH', src_ip, dst_ip, 0, 6, len(tcp_header + options))
            checksum = self.getTCPChecksum(pseudo + tcp_header + options)
            tcp_header = struct.pack('!HHLLBBHHH',
                self.l4_field['src_port'],
                self.l4_field['dest_port'],
                self.l4_field['seq'],
                self.l4_field['ack_num'],
                offset << 4,
                self.l4_field.get('flags', 0x12),
                window,
                checksum,
                self.l4_field.get('urgent_ptr', 0)
            )

            total_len = settings.IP_HEADER_LEN + len(tcp_header) + len(options)
            ip_header = struct.pack('!BBHHHBBH4s4s',
                0x45,
                tos,
                total_len,
                self.l3_field.get('pktID', 54321),
                self.l3_field.get('FRAGMENT_STATUS', 0),
                ttl,
                proto,
                0,
                src_ip,
                dst_ip
            )
            ip_checksum = self.getTCPChecksum(ip_header)
            ip_header = struct.pack('!BBHHHBBH4s4s',
                0x45,
                tos,
                total_len,
                self.l3_field.get('pktID', 54321),
                self.l3_field.get('FRAGMENT_STATUS', 0),
                ttl,
                proto,
                ip_checksum,
                src_ip,
                dst_ip
            )
            self.packet = ip_header + tcp_header + options
        except Exception as e:
            logging.error(f"[Packet] Packing error: {e}")

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
