# src/fingerprint_utils.py
import struct
import logging
import copy

def generateKey(packet, proto_type):
    pkt = copy.deepcopy(packet)

    # Normalize IP fields
    if hasattr(pkt, 'ip'):
        pkt.ip.ttl = 0
        pkt.ip.id = 0
        pkt.ip.checksum = 0

    # Normalize TCP/UDP fields
    if proto_type == 'TCP' and hasattr(pkt, 'tcp'):
        pkt.tcp.seq = 0
        pkt.tcp.ack = 0
        pkt.tcp.window = 0
        pkt.tcp.checksum = 0
        pkt.tcp.urgent_pointer = 0
        pkt.tcp.options = [opt for opt in pkt.tcp.options if opt[0] not in ['Timestamp', 'SACK']]

    elif proto_type == 'UDP' and hasattr(pkt, 'udp'):
        pkt.udp.checksum = 0
        pkt.udp.length = 0

    elif proto_type == 'ICMP' and hasattr(pkt, 'icmp'):
        pkt.icmp.checksum = 0
        pkt.icmp.id = 0
        pkt.icmp.seq = 0

    # Return a string key based on normalized fields
    return pkt.get_signature()

def gen_key(proto: str, packet: bytes):
    if proto == 'tcp':
        return gen_tcp_key(packet)
    elif proto == 'icmp':
        return gen_icmp_key(packet)
    elif proto == 'udp':
        return gen_udp_key(packet)
    elif proto == 'arp':
        return gen_arp_key(packet)
    return b'', None

def gen_tcp_key(packet: bytes):
    try:
        ip_header = packet[14:34]
        tcp_header = packet[34:54]
        src_port, dest_port, seq, ack_num, offset_flags = struct.unpack('!HHLLH', tcp_header[:14])
        offset = (offset_flags >> 12) * 4
        payload = packet[54:54+offset-20]
        ip_key = ip_header[:8] + b'\x00' * 8
        tcp_key = struct.pack('!HHLLH', 0, dest_port, 0, 0, offset_flags) + tcp_header[14:20]
        return ip_key + tcp_key + payload, None
    except Exception as e:
        logging.warning(f"\u26a0\ufe0f gen_tcp_key failed: {e}")
        return b'', None

def gen_udp_key(packet: bytes):
    try:
        ip_header = packet[14:34]
        udp_header = packet[34:42]
        payload = packet[42:]
        ip_key = ip_header[:8] + b'\x00' * 8
        udp_key = struct.pack('!HHH', 0, 0, 8) + b'\x00\x00'
        return ip_key + udp_key + payload, None
    except Exception as e:
        logging.warning(f"\u26a0\ufe0f gen_udp_key failed: {e}")
        return b'', None

def gen_icmp_key(packet: bytes):
    try:
        ip_header = packet[14:34]
        icmp_header = packet[34:42]
        ip_key = ip_header[:8] + b'\x00' * 8
        icmp_type, code, _, _, _ = struct.unpack('!BBHHH', icmp_header)
        icmp_key = struct.pack('!BBHHH', icmp_type, code, 0, 0, 0)
        return ip_key + icmp_key, None
    except Exception as e:
        logging.warning(f"\u26a0\ufe0f gen_icmp_key failed: {e}")
        return b'', None

def gen_arp_key(packet: bytes):
    try:
        arp_header = packet[14:42]
        fields = struct.unpack('!HHBBH6s4s6s4s', arp_header)
        key = struct.pack('!HHBBH6s4s6s4s',
                          fields[0], fields[1], fields[2], fields[3], fields[4],
                          b'\x00'*6, b'\x00'*4, b'\x00'*6, b'\x00'*4)
        return key, None
    except Exception as e:
        logging.warning(f"\u26a0\ufe0f gen_arp_key failed: {e}")
        return b'', None
