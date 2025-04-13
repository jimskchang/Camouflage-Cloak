# src/fingerprint_utils.py

import hashlib
import logging
import struct

def gen_key(proto: str, packet: bytes):
    try:
        if proto == 'tcp':
            return gen_tcp_key(packet), proto
        elif proto == 'udp':
            return gen_udp_key(packet), proto
        elif proto == 'icmp':
            return gen_icmp_key(packet), proto
        elif proto == 'arp':
            return gen_arp_key(packet), proto
        else:
            return b'', proto
    except Exception as e:
        logging.warning(f"[gen_key] failed for {proto.upper()}: {e}")
        return b'', proto

def normalize_and_hash(fields):
    try:
        byte_fields = []
        for field in fields:
            if isinstance(field, int):
                field = min(max(field, 0), 0xFFFFFFFF)
                byte_fields.append(field.to_bytes(4, 'big'))
            elif isinstance(field, str):
                byte_fields.append(field.encode())
            elif isinstance(field, bytes):
                byte_fields.append(field)
            elif field is None:
                byte_fields.append(b'\x00' * 4)
            else:
                logging.debug(f"[normalize] Skipped unsupported field type: {type(field)}")
        flat = b''.join(byte_fields)
        return hashlib.sha256(flat).digest()
    except Exception as e:
        logging.warning(f"[normalize_and_hash] error: {e}")
        return b''

def gen_tcp_key(packet: bytes):
    try:
        tcp_hdr = packet[34:54]
        src_port, dst_port, seq, ack, offset_flags, win, chk, urg = struct.unpack('!HHLLHHHH', tcp_hdr[:20])
        ttl = packet[22]
        tos = packet[15]
        fields = [ttl, tos, 0, dst_port, 0, 0, offset_flags & 0xFFF, win, chk, urg]
        return normalize_and_hash(fields)
    except Exception as e:
        logging.warning(f"[gen_tcp_key] failed: {e}")
        return b''

def gen_udp_key(packet: bytes):
    try:
        udp_hdr = packet[34:42]
        src_port, dst_port, length, checksum = struct.unpack('!HHHH', udp_hdr[:8])
        ttl = packet[22]
        tos = packet[15]
        fields = [ttl, tos, 0, dst_port, length, checksum]
        return normalize_and_hash(fields)
    except Exception as e:
        logging.warning(f"[gen_udp_key] failed: {e}")
        return b''

def gen_icmp_key(packet: bytes):
    try:
        icmp_hdr = packet[34:42]
        icmp_type, code, checksum, id, seq = struct.unpack('!BBHHH', icmp_hdr[:8])
        ttl = packet[22]
        tos = packet[15]
        fields = [ttl, tos, icmp_type, code, checksum, id, seq]
        return normalize_and_hash(fields)
    except Exception as e:
        logging.warning(f"[gen_icmp_key] failed: {e}")
        return b''

def gen_arp_key(packet: bytes):
    try:
        arp_hdr = packet[14:42]
        htype, ptype, hlen, plen, op = struct.unpack('!HHBBH', arp_hdr[:8])
        fields = [htype, ptype, hlen, plen, op]
        return normalize_and_hash(fields)
    except Exception as e:
        logging.warning(f"[gen_arp_key] failed: {e}")
        return b''
