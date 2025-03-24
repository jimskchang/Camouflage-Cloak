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
            self.l2_header = self.packet[:settings.ETH_HEADER_LEN]
            eth_dMAC, eth_sMAC, eth_protocol = struct.unpack('!6s6sH', self.l2_header)
            self.l3 = {0x0800: 'ip', 0x0806: 'arp'}.get(eth_protocol, 'others')
            self.l2_field = {
                'dMAC': eth_dMAC,
                'sMAC': eth_sMAC,
                'protocol': eth_protocol,
            }
        except Exception as e:
            logging.error(f"[L2] Error unpacking Ethernet: {e}")

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
            if len(self.packet) < settings.ETH_HEADER_LEN + settings.ARP_HEADER_LEN:
                raise ValueError("Packet too short for ARP header.")
            self.l3_header = self.packet[settings.ETH_HEADER_LEN : settings.ETH_HEADER_LEN + settings.ARP_HEADER_LEN]
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
            if len(self.packet) < settings.ETH_HEADER_LEN + settings.IP_HEADER_LEN:
                raise ValueError("Packet too short for IP header.")
            self.l3_header = self.packet[settings.ETH_HEADER_LEN : settings.ETH_HEADER_LEN + settings.IP_HEADER_LEN]
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
                'dest_IP': fields[9]
            }
        except Exception as e:
            logging.error(f"[IP] Error unpacking: {e}")

    def unpack_tcp_header(self) -> None:
        try:
            tcp_start = settings.ETH_HEADER_LEN + settings.IP_HEADER_LEN
            self.l4_header = self.packet[tcp_start : tcp_start + settings.TCP_HEADER_LEN]
            fields = struct.unpack('!HHLLBBHHH', self.l4_header)
            self.l4_field = {
                'src_port': fields[0],
                'dest_port': fields[1],
                'seq': fields[2],
                'ack_num': fields[3],
                'offset': (fields[4] >> 4) * 4,
                'flags': fields[5],
                'window': self.window_override if self.window_override is not None else fields[6],
                'checksum': fields[7],
                'urgent_ptr': fields[8],
                'kind_seq': [],
                'option_field': {}
            }

            # Try parse TCP options
            option_data = self.packet[tcp_start + settings.TCP_HEADER_LEN : tcp_start + fields[4] * 4]
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
                    value = option_data[i + 2 : i + length]
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
            udp_start = settings.ETH_HEADER_LEN + settings.IP_HEADER_LEN
            self.l4_header = self.packet[udp_start : udp_start + settings.UDP_HEADER_LEN]
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
            icmp_start = settings.ETH_HEADER_LEN + settings.IP_HEADER_LEN
            self.l4_header = self.packet[icmp_start : icmp_start + settings.ICMP_HEADER_LEN]
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

    def pack(self) -> None:
        """Rebuilds the packet from fields, including TCP options if available"""
        try:
            # --- Ethernet Layer ---
            eth = struct.pack('!6s6sH',
                self.l2_field.get('dMAC', b'\x00' * 6),
                self.l2_field.get('sMAC', b'\x00' * 6),
                self.l2_field.get('protocol', 0x0800)
            )

            if self.l3 == 'arp':
                arp_header = struct.pack(
                    '!HHBBH6s4s6s4s',
                    self.l3_field.get('hw_type', 1),
                    self.l3_field.get('proto_type', 0x0800),
                    self.l3_field.get('hw_size', 6),
                    self.l3_field.get('proto_size', 4),
                    self.l3_field.get('opcode', 2),
                    self.l3_field.get('sender_mac', b'\x00' * 6),
                    self.l3_field.get('sender_ip', b'\x00' * 4),
                    self.l3_field.get('recv_mac', b'\x00' * 6),
                    self.l3_field.get('recv_ip', b'\x00' * 4)
                )
                self.packet = eth + arp_header
                return

            # --- IP Layer ---
            src_ip = self.l3_field.get('src_IP', b'\x00\x00\x00\x00')
            dst_ip = self.l3_field.get('dest_IP', b'\x00\x00\x00\x00')
            ttl = self.l3_field.get('ttl', 64)
            proto = self.l3_field.get('PROTOCOL', 6)

            # --- TCP Layer ---
            options = b''
            if self.l4 == 'tcp':
                kind_seq = self.l4_field.get('kind_seq', [])
                opt = self.l4_field.get('option_field', {})

                for kind in kind_seq:
                    if kind == 1:
                        options += struct.pack('!B', 1)
                    elif kind == 2 and 'mss' in opt:
                        options += struct.pack('!BBH', 2, 4, opt['mss'])
                    elif kind == 3 and 'ws' in opt:
                        options += struct.pack('!BBB', 3, 3, opt['ws'])
                    elif kind == 8 and 'ts_val' in opt and 'ts_echo_reply' in opt:
                        options += struct.pack('!BBII', 8, 10, opt['ts_val'], opt['ts_echo_reply'])

                while len(options) % 4 != 0:
                    options += struct.pack('!B', 0)

                offset = 5 + len(options) // 4
                tcp_header = struct.pack('!HHLLBBHHH',
                    self.l4_field['src_port'],
                    self.l4_field['dest_port'],
                    self.l4_field['seq'],
                    self.l4_field['ack_num'],
                    offset << 4,
                    self.l4_field.get('flags', 0x12),
                    self.l4_field['window'],
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
                    self.l4_field['window'],
                    checksum,
                    self.l4_field.get('urgent_ptr', 0)
                )
                self.l4_header = tcp_header + options

            # IP total_len
            total_len = settings.IP_HEADER_LEN + len(self.l4_header)
            ip_header = struct.pack('!BBHHHBBH4s4s',
                0x45, 0, total_len, 54321, 0,
                ttl, proto, 0, src_ip, dst_ip
            )
            checksum = self.getTCPChecksum(ip_header)
            ip_header = struct.pack('!BBHHHBBH4s4s',
                0x45, 0, total_len, 54321, 0,
                ttl, proto, checksum, src_ip, dst_ip
            )
            self.l3_header = ip_header

            self.packet = eth + ip_header + self.l4_header

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
