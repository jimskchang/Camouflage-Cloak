import socket
import binascii
import struct
import array
import time
import src.settings as settings

class TcpConnect:
    def __init__(self, host):
        """
        Initializes a raw socket connection for TCP packet manipulation.
        Reads the MAC address from the NIC settings and binds the socket.
        """
        self.dip = host
        
        try:
            with open(settings.NICAddr) as f:
                mac = f.readline().strip()
                self.mac = binascii.unhexlify(mac.replace(':', ''))  # Fixed MAC parsing
        except FileNotFoundError:
            raise ValueError(f"Error: NIC address file {settings.NICAddr} not found.")

        self.sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
        self.sock.bind((settings.NIC, 0))

    def build_tcp_header_from_reply(self, tcp_len, seq, ack_num, src_port, dest_port, src_IP, dest_IP, flags):
        """
        Build a TCP header with a correct checksum for reply packets.
        """
        offset = (tcp_len // 4) << 4  # Ensure proper 4-bit shifting
        reply_tcp_header = struct.pack('!HHIIBBHHH', src_port, dest_port, seq, ack_num, offset, flags, 0, 0, 0)
        
        # Construct Pseudo Header for Checksum
        pseudo_hdr = struct.pack('!4s4sBBH', src_IP, dest_IP, 0, socket.IPPROTO_TCP, len(reply_tcp_header))
        checksum = TcpConnect.getTCPChecksum(pseudo_hdr + reply_tcp_header)
        
        # Insert the computed checksum
        reply_tcp_header = reply_tcp_header[:16] + struct.pack('!H', checksum) + reply_tcp_header[18:]
        return reply_tcp_header

    @staticmethod
    def getTCPChecksum(packet: bytes) -> int:
        """
        Compute TCP checksum to ensure data integrity in TCP packets.
        """
        if len(packet) % 2 != 0:
            packet += b'\0'
        res = sum(array.array("H", packet))
        res = (res >> 16) + (res & 0xffff)
        res += res >> 16
        return (~res) & 0xffff


def os_build_tcp_header_from_reply(tcp_len, seq, ack_num, src_port, dest_port, src_IP, dest_IP, flags, window, reply_tcp_option):
    """
    Build an OS deception TCP header with options and correct checksum.
    """
    offset = (tcp_len // 4) << 4
    reply_tcp_header = struct.pack('!HHIIBBHHH', src_port, dest_port, seq, ack_num, offset, flags, window, 0, 0)
    reply_tcp_header_option = reply_tcp_header + reply_tcp_option

    # Construct Pseudo Header for Checksum
    pseudo_hdr = struct.pack('!4s4sBBH', src_IP, dest_IP, 0, socket.IPPROTO_TCP, len(reply_tcp_header_option))
    checksum = TcpConnect.getTCPChecksum(pseudo_hdr + reply_tcp_header_option)

    reply_tcp_header_option = reply_tcp_header_option[:16] + struct.pack('!H', checksum) + reply_tcp_header_option[18:]
    return reply_tcp_header_option


def unpack_tcp_option(tcp_option):
    """
    Unpack TCP options and handle unexpected cases gracefully.
    """
    start_ptr = 0
    kind_seq = []
    option_val = {'padding': [], 'mss': None, 'shift_count': None, 'sack_permitted': None, 'ts_val': None, 'ts_echo_reply': None}

    while start_ptr < len(tcp_option):
        try:
            kind = tcp_option[start_ptr]
            start_ptr += 1

            if kind == 1:
                option_val['padding'] = True
                kind_seq.append(kind)
            elif kind in [2, 3, 4, 8]:
                if start_ptr >= len(tcp_option):
                    break  # Prevents out-of-bounds error
                length = tcp_option[start_ptr]
                start_ptr += 1
                if kind == 2:
                    option_val['mss'], = struct.unpack('!H', tcp_option[start_ptr:start_ptr + 2])
                elif kind == 3:
                    option_val['shift_count'], = struct.unpack('!B', tcp_option[start_ptr:start_ptr + 1])
                elif kind == 4:
                    option_val['sack_permitted'] = True
                elif kind == 8:
                    option_val['ts_val'], option_val['ts_echo_reply'] = struct.unpack('!LL', tcp_option[start_ptr:start_ptr + 8])
                start_ptr += length - 2
                kind_seq.append(kind)
        except struct.error:
            break  # Prevents crash if unexpected TCP options are found
    
    return option_val, kind_seq


def byte2mac(mac_byte: bytes) -> str:
    """
    Convert a MAC address from byte format to human-readable string format.
    """
    return "%02x:%02x:%02x:%02x:%02x:%02x" % struct.unpack("BBBBBB", mac_byte)


def byte2ip(ip_byte: bytes) -> str:
    """
    Convert an IP address from byte format to human-readable string format.
    """
    return socket.inet_ntoa(ip_byte)
