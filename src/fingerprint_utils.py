# src/fingerprint_utils.py

import struct
import logging

def gen_key(proto: str, packet: bytes):
    """
    Dispatch to appropriate key generator by protocol.

    Args:
        proto: 'tcp', 'udp', 'icmp', or 'arp'
        packet: raw packet bytes

    Returns:
        Tuple: (normalized key bytes, optional metadata)
    """
    proto = proto.lower()
    if proto == 'tcp':
        return gen_tcp_key(packet)
    elif proto == 'udp':
        return gen_udp_key(packet)
    elif proto == 'icmp':
        return gen_icmp_key(packet)
    elif proto == 'arp':
        return gen_arp_key(packet)
    return b'', None

def gen_tcp_key(packet: bytes):
    try:
        ip_header = packet[14:34]
        tcp_header = packet[34:54]
        offset_flags = struct.unpack('!H', tcp_header[12:14])[0]
        offset = ((offset_flags >> 12) & 0xF) * 4
        payload = packet[34 + offset:]

        ip_key = ip_header[:8] + b'\x00' * 8
        tcp_key = tcp_header[:2] + b'\x00\x00' + b'\x00\x00\x00\x00'  # zero seq/ack
        tcp_key += tcp_header[12:20]  # offset/flags/window
        tcp_key += b'\x00\x00'  # zero checksum
        return ip_key + tcp_key + payload[:16], None
    except Exception as e:
        logging.warning(f"⚠️ gen_tcp_key failed: {e}")
        return b'', None

def gen_udp_key(packet: bytes):
    try:
        ip_header = packet[14:34]
        udp_header = packet[34:42]
        payload = packet[42:58]

        ip_key = ip_header[:8] + b'\x00' * 8
        udp_key = udp_header[:2] + b'\x00\x00' + b'\x00\x00\x00\x00'
        return ip_key + udp_key + payload, None
    except Exception as e:
        logging.warning(f"⚠️ gen_udp_key failed: {e}")
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
        logging.warning(f"⚠️ gen_icmp_key failed: {e}")
        return b'', None

def gen_arp_key(packet: bytes):
    try:
        arp_header = packet[14:42]
        fields = struct.unpack('!HHBBH6s4s6s4s', arp_header)
        key = struct.pack('!HHBBH6s4s6s4s',
                          fields[0], fields[1], fields[2], fields[3], fields[4],
                          b'\x00' * 6, b'\x00' * 4, b'\x00' * 6, b'\x00' * 4)
        return key, None
    except Exception as e:
        logging.warning(f"⚠️ gen_arp_key failed: {e}")
        return b'', None
