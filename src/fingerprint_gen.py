import logging
import socket
import struct
import array

import src.settings as settings
from src.fingerprint_gen import generateKey


class Packet:
    """
    Network packet parser for Ethernet, IPv4/ARP, TCP/UDP, and ICMP.
    
    Unpacks raw binary packet data layer-by-layer (L2→L3→L4) into structured
    field dictionaries. Supports fingerprinting for flow identification and
    deception matching.
    
    Attributes:
        packet (bytes): Raw packet data
        l3 (str): Layer 3 protocol ('ip', 'arp', 'others')
        l4 (str): Layer 4 protocol ('tcp', 'udp', 'icmp', 'others', or '')
        l2_field (dict): Parsed L2 (Ethernet/VLAN) fields
        l3_field (dict): Parsed L3 (IP/ARP) fields
        l4_field (dict): Parsed L4 (TCP/UDP/ICMP) fields
        l2_header, l3_header, l4_header (bytes): Raw header bytes
        interface (str): Network interface name (optional)
        ttl_override (int): Override TTL value if set
        window_override (int): Override TCP window if set
    """
    
    def __init__(
        self,
        packet=b'',
        proc=None,
        l2_field=None,
        l3_field=None,
        l4_field=None,
        data='',
        ttl=None,
        window=None,
    ):
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
        """
        Generate a stable fingerprint hash of this packet.
        
        Args:
            proto_type (str): Protocol to fingerprint ("tcp", "udp", "icmp", etc.)
        
        Returns:
            bytes: SHA-256 digest, or b'' on error.
        """
        try:
            return generateKey(self, proto_type)
        except Exception as e:
            logging.warning(f"[Packet] Failed to get signature for {proto_type}: {e}")
            return b''
    
    def unpack(self) -> None:
        """
        Parse raw packet data layer-by-layer with strict gatekeeping.
        
        If L2 or L3 parsing fails, the parse stops early (no cascading errors).
        L4 parsing failures are non-fatal; parsing continues if L2/L3 succeed.
        
        Populates l2_field, l3_field, l4_field with structured data.
        """
        try:
            if len(self.packet) < 14:
                logging.debug("[Packet] Packet too short for L2 header")
                return
            
            if not self.unpack_l2_header():
                logging.debug("[Packet] L2 header parsing failed")
                return
            
            if not self.unpack_l3_header():
                logging.debug("[Packet] L3 header parsing failed")
                return
            
            # L4 parsing is best-effort (some packets have no L4)
            self.unpack_l4_header()
        
        except Exception as e:
            logging.debug(f"[Packet] Unpack error: {e}")
    
    def unpack_l2_header(self) -> bool:
        """
        Parse Ethernet/VLAN header (802.3 or 802.1Q-tagged).
        
        Returns:
            bool: True if parsing succeeded, False otherwise.
        """
        try:
            if len(self.packet) < 14:
                return False
            
            eth_dMAC, eth_sMAC, eth_type = struct.unpack('!6s6sH', self.packet[:14])
            eth_dMAC_str = ':'.join(f'{b:02x}' for b in eth_dMAC)
            eth_sMAC_str = ':'.join(f'{b:02x}' for b in eth_sMAC)
            
            # Check for VLAN tag (802.1Q)
            if eth_type == 0x8100:
                if len(self.packet) < 18:
                    return False
                
                vlan_tag = struct.unpack('!H', self.packet[14:16])[0]
                real_eth_type = struct.unpack('!H', self.packet[16:18])[0]
                
                self.l2_field = {
                    'dMAC': eth_dMAC_str,
                    'sMAC': eth_sMAC_str,
                    'protocol': real_eth_type,
                    'vlan': vlan_tag & 0x0FFF,
                }
                self.l3 = {0x0800: 'ip', 0x0806: 'arp'}.get(real_eth_type, 'others')
                self.l2_header = self.packet[:18]
            else:
                self.l2_field = {
                    'dMAC': eth_dMAC_str,
                    'sMAC': eth_sMAC_str,
                    'protocol': eth_type,
                    'vlan': None,
                }
                self.l3 = {0x0800: 'ip', 0x0806: 'arp'}.get(eth_type, 'others')
                self.l2_header = self.packet[:14]
            
            return True
        
        except Exception as e:
            logging.error(f"[L2] Unpack error: {e}")
            return False
    
    def unpack_l3_header(self) -> bool:
        """
        Parse Layer 3 header (IP or ARP based on self.l3).
        
        Returns:
            bool: True if parsing succeeded, False otherwise.
        """
        if self.l3 == 'ip':
            return self.unpack_ip_header()
        elif self.l3 == 'arp':
            return self.unpack_arp_header()
        return False
    
    def unpack_l4_header(self) -> bool:
        """
        Parse Layer 4 header (TCP, UDP, ICMP based on self.l4).
        
        This is best-effort; returns True for protocols without L4 data (like ICMP).
        
        Returns:
            bool: True if no error, False only on structural parsing failure.
        """
        try:
            if self.l4 == 'tcp':
                self.unpack_tcp_header()
                return True
            
            if self.l4 == 'udp':
                return self.unpack_udp_header()
            
            # Non-TCP/UDP protocols: ICMP, others are valid but may not have standard L4 parsing
            if self.l4 in ('icmp', 'others', ''):
                return True
            
            return False
        
        except Exception as e:
            logging.debug(f"[L4] Unpack error: {e}")
            return False
    
    def unpack_arp_header(self) -> bool:
        """
        Parse ARP header (RFC 826).
        
        Returns:
            bool: True if parsing succeeded, False otherwise.
        """
        try:
            start = len(self.l2_header)
            if len(self.packet) < start + settings.ARP_HEADER_LEN:
                return False
            
            self.l3_header = self.packet[start:start + settings.ARP_HEADER_LEN]
            fields = struct.unpack('!HHBBH6s4s6s4s', self.l3_header)
            
            self.l3_field = {
                'hw_type': fields[0],
                'proto_type': fields[1],
                'hw_size': fields[2],
                'proto_size': fields[3],
                'opcode': fields[4],
                'sender_mac': ':'.join(f'{b:02x}' for b in fields[5]),
                'sender_ip': socket.inet_ntoa(fields[6]),
                'recv_mac': ':'.join(f'{b:02x}' for b in fields[7]),
                'recv_ip': socket.inet_ntoa(fields[8]),
                'src_IP_str': socket.inet_ntoa(fields[6]),
                'dest_IP_str': socket.inet_ntoa(fields[8]),
            }
            
            return True
        
        except Exception as e:
            logging.error(f"[ARP] Unpack error: {e}")
            return False
    
    def unpack_ip_header(self) -> bool:
        """
        Parse IPv4 header (RFC 791).
        
        Returns:
            bool: True if parsing succeeded, False otherwise.
        """
        try:
            start = len(self.l2_header)
            if len(self.packet) < start + 20:
                return False
            
            version_ihl = self.packet[start]
            ihl = version_ihl & 0x0F
            version = version_ihl >> 4
            
            # Validate version and header length
            if version != 4 or ihl < 5:
                return False
            
            header_len = ihl * 4
            if len(self.packet) < start + header_len:
                return False
            
            self.l3_header = self.packet[start:start + header_len]
            fields = struct.unpack('!BBHHHBBH4s4s', self.l3_header[:20])
            
            # Determine L4 protocol
            protocol_num = fields[6]
            self.l4 = {1: 'icmp', 6: 'tcp', 17: 'udp'}.get(protocol_num, 'others')
            
            # Build field dictionary with standardized key names for fingerprinting
            self.l3_field = {
                'IHL_VERSION': version_ihl,  # Raw version/IHL byte
                'VERSION': version,
                'IHL': ihl,
                'TOS': fields[1],  # Type of Service / DSCP
                'total_length': fields[2],
                'identification': fields[3],
                'flags': fields[4] >> 13,
                'fragment_offset': fields[4] & 0x1FFF,
                'ttl': self.ttl_override if self.ttl_override is not None else fields[5],
                'PROTOCOL': protocol_num,
                'checksum': fields[7],
                'src_IP_str': socket.inet_ntoa(fields[8]),
                'dest_IP_str': socket.inet_ntoa(fields[9]),
                'options': self.l3_header[20:],
            }
            
            return True
        
        except Exception as e:
            logging.error(f"[IP] Unpack error: {e}")
            return False
    
    def unpack_udp_header(self) -> bool:
        """
        Parse UDP header (RFC 768).
        
        Returns:
            bool: True if parsing succeeded, False otherwise.
        """
        try:
            if not self.l3_field:
                return False
            
            ihl = self.l3_field.get('IHL', 5)
            start = len(self.l2_header) + (ihl * 4)
            if len(self.packet) < start + 8:
                return False
            
            self.l4_header = self.packet[start:start + 8]
            fields = struct.unpack('!HHHH', self.l4_header)
            
            self.l4_field = {
                'src_port': fields[0],
                'dest_port': fields[1],
                'length': fields[2],
                'checksum': fields[3],
            }
            
            return True
        
        except Exception as e:
            logging.debug(f"[UDP] Unpack error: {e}")
            return False
    
    def unpack_tcp_header(self) -> None:
        """
        Parse TCP header (RFC 793) with robust options parsing.
        
        Handles variable-length TCP options (MSS, Window Scale, Timestamps).
        Validates data offset and bounds to prevent buffer overruns.
        """
        try:
            if self.l3 != 'ip' or not self.l3_field:
                return
            
            ihl = self.l3_field.get('IHL', 5)
            start = len(self.l2_header) + (ihl * 4)
            if len(self.packet) < start + 20:
                return
            
            # Parse data offset from byte 12 of TCP header
            data_offset_byte = self.packet[start + 12]
            offset = (data_offset_byte >> 4) & 0x0F
            
            if offset < 5:
                return
            
            header_len = offset * 4
            if len(self.packet) < start + header_len:
                return
            
            self.l4_header = self.packet[start:start + header_len]
            fields = struct.unpack('!HHLLBBHHH', self.l4_header[:20])
            
            self.l4_field = {
                'src_port': fields[0],
                'dest_port': fields[1],
                'seq': fields[2],
                'ack_num': fields[3],
                'data_offset': offset,
                'flags': fields[5],
                'window': self.window_override if self.window_override is not None else fields[6],
                'checksum': fields[7],
                'urgent_pointer': fields[8],
                'option_field': {},
            }
            
            # Parse TCP Options (variable length)
            option_data = self.l4_header[20:header_len]
            i = 0
            while i < len(option_data):
                kind = option_data[i]
                
                # End of Options List
                if kind == 0:
                    break
                
                # No-Operation (NOP)
                if kind == 1:
                    i += 1
                    continue
                
                # All other options have a length field at i+1
                if i + 1 >= len(option_data):
                    break
                
                length = option_data[i + 1]
                if length < 2 or (i + length) > len(option_data):
                    break  # Invalid option length; stop parsing
                
                value = option_data[i + 2:i + length]
                
                # Maximum Segment Size (MSS, kind=2)
                if kind == 2 and len(value) >= 2:
                    self.l4_field['option_field']['mss'] = struct.unpack('!H', value[:2])[0]
                
                # Window Scale (WSCALE, kind=3)
                elif kind == 3 and len(value) >= 1:
                    self.l4_field['option_field']['ws'] = struct.unpack('!B', value[:1])[0]
                
                # Selective ACK (SACK, kind=5) - store length only
                elif kind == 5:
                    self.l4_field['option_field']['sack_length'] = length
                
                # Timestamps (kind=8)
                elif kind == 8 and len(value) >= 8:
                    ts_val, ts_echo_reply = struct.unpack('!II', value[:8])
                    self.l4_field['option_field']['ts_val'] = ts_val
                    self.l4_field['option_field']['ts_echo_reply'] = ts_echo_reply
                
                i += length
        
        except Exception as e:
            logging.debug(f"[TCP] Unpack error: {e}")
    
    @staticmethod
    def getTCPChecksum(packet: bytes) -> int:
        """
        Calculate TCP/IP checksum using RFC 1071 algorithm.
        
        Args:
            packet (bytes): The data to checksum.
        
        Returns:
            int: 16-bit checksum value (0x0000 - 0xFFFF).
        """
        if len(packet) % 2 != 0:
            packet += b'\0'
        
        res = sum(array.array("H", packet))
        res = (res >> 16) + (res & 0xFFFF)
        res += res >> 16
        return (~res) & 0xFFFF
    
    @staticmethod
    def getIPChecksum(packet: bytes) -> int:
        """
        Calculate IPv4 header checksum using RFC 1071 algorithm.
        
        Args:
            packet (bytes): IPv4 header (typically 20 bytes).
        
        Returns:
            int: 16-bit checksum value.
        """
        return Packet.getTCPChecksum(packet)
