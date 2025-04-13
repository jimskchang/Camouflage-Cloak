# src/ja3_extractor.py

import logging
import hashlib
import struct
from scapy.all import TCP, Raw
from src.settings import JA3_RULES

def extract_ja3(packet_bytes: bytes) -> str:
    """
    Extracts a JA3 fingerprint from raw TCP packet bytes.
    Returns MD5 hash of the JA3 string.
    """
    try:
        if len(packet_bytes) < 54:
            return None

        tcp_payload = packet_bytes[54:]
        if tcp_payload[0] != 0x16:  # TLS Handshake Content Type
            return None

        if tcp_payload[5] != 0x01:  # Handshake Type: ClientHello
            return None

        version = struct.unpack("!H", tcp_payload[1:3])[0]
        session_id_len = tcp_payload[43]
        index = 44 + session_id_len

        cipher_len = struct.unpack("!H", tcp_payload[index:index + 2])[0]
        index += 2
        ciphers = []
        for i in range(0, cipher_len, 2):
            cipher = struct.unpack("!H", tcp_payload[index + i:index + i + 2])[0]
            ciphers.append(str(cipher))
        index += cipher_len

        comp_methods_len = tcp_payload[index]
        index += 1 + comp_methods_len

        ext_total_len = struct.unpack("!H", tcp_payload[index:index + 2])[0]
        index += 2

        exts = []
        elliptic_curves = []
        ec_point_formats = []

        ext_end = index + ext_total_len
        while index + 4 <= ext_end:
            ext_type = struct.unpack("!H", tcp_payload[index:index + 2])[0]
            ext_len = struct.unpack("!H", tcp_payload[index + 2:index + 4])[0]
            ext_data = tcp_payload[index + 4:index + 4 + ext_len]

            exts.append(str(ext_type))
            if ext_type == 10:  # Elliptic Curves
                el_len = struct.unpack("!H", ext_data[:2])[0]
                for i in range(2, 2 + el_len, 2):
                    curve = struct.unpack("!H", ext_data[i:i + 2])[0]
                    elliptic_curves.append(str(curve))
            elif ext_type == 11:  # EC Point Formats
                for b in ext_data[1:]:
                    ec_point_formats.append(str(b))

            index += 4 + ext_len

        ja3_str = f"{version}," \
                  f"{'-'.join(ciphers)}," \
                  f"0," \
                  f"{'-'.join(elliptic_curves)}," \
                  f"{'-'.join(ec_point_formats)}"

        return hashlib.md5(ja3_str.encode()).hexdigest()

    except Exception as e:
        logging.warning(f"[JA3] Extraction failed: {e}")
        return None

def match_ja3_rule(ja3_hash: str) -> dict:
    """
    Returns matched JA3 rule (from settings.JA3_RULES) by hash.
    """
    try:
        for rule in JA3_RULES:
            if rule.get("ja3") == ja3_hash:
                return rule
    except Exception as e:
        logging.warning(f"[JA3] match_ja3_rule error: {e}")
    return None
