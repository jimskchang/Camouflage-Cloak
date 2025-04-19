# src/ja3_extractor.py

import logging
import hashlib
import struct
from scapy.all import TCP
from src.settings import JA3_RULES

def extract_ja3(packet_bytes: bytes) -> str:
    """
    Extract a JA3 fingerprint from raw TCP packet bytes.
    Returns the MD5 hash of the JA3 string, or None on failure.
    """
    try:
        if len(packet_bytes) < 60:
            return None

        tcp_payload = packet_bytes[54:]
        if not (tcp_payload and tcp_payload[0] == 0x16 and tcp_payload[5] == 0x01):
            return None  # Not TLS ClientHello

        version = struct.unpack("!H", tcp_payload[1:3])[0]

        session_id_len = tcp_payload[43]
        index = 44 + session_id_len
        if index + 2 > len(tcp_payload):
            return None

        # --- Ciphers ---
        cipher_len = struct.unpack("!H", tcp_payload[index:index + 2])[0]
        index += 2
        ciphers = []
        for i in range(0, cipher_len, 2):
            if index + i + 2 > len(tcp_payload):
                return None
            cipher = struct.unpack("!H", tcp_payload[index + i:index + i + 2])[0]
            ciphers.append(str(cipher))
        index += cipher_len

        if index + 1 > len(tcp_payload):
            return None
        comp_methods_len = tcp_payload[index]
        index += 1 + comp_methods_len

        if index + 2 > len(tcp_payload):
            return None
        ext_total_len = struct.unpack("!H", tcp_payload[index:index + 2])[0]
        index += 2
        ext_end = index + ext_total_len

        exts = []
        curves = []
        ec_formats = []

        while index + 4 <= ext_end and index + 4 <= len(tcp_payload):
            ext_type = struct.unpack("!H", tcp_payload[index:index + 2])[0]
            ext_len = struct.unpack("!H", tcp_payload[index + 2:index + 4])[0]
            ext_data = tcp_payload[index + 4:index + 4 + ext_len]

            exts.append(str(ext_type))

            if ext_type == 10 and len(ext_data) >= 2:
                curve_len = struct.unpack("!H", ext_data[:2])[0]
                for i in range(2, 2 + curve_len, 2):
                    if i + 2 <= len(ext_data):
                        curve = struct.unpack("!H", ext_data[i:i + 2])[0]
                        curves.append(str(curve))
            elif ext_type == 11 and len(ext_data) >= 1:
                ec_formats += [str(b) for b in ext_data[1:]]

            index += 4 + ext_len

        ja3_str = f"{version}," \
                  f"{'-'.join(ciphers)}," \
                  f"0," \
                  f"{'-'.join(curves)}," \
                  f"{'-'.join(ec_formats)}"

        ja3_hash = hashlib.md5(ja3_str.encode()).hexdigest()
        logging.debug(f"[JA3] {ja3_str} → {ja3_hash}")
        return ja3_hash

    except Exception as e:
        logging.warning(f"[JA3] extract_ja3 failed: {e}")
        return None

def extract_ja3_from_packet(pkt) -> str:
    try:
        return extract_ja3(pkt.packet)
    except Exception as e:
        logging.warning(f"[JA3] extract_ja3_from_packet error: {e}")
        return None

def match_ja3_rule(ja3_hash: str) -> dict:
    """
    Matches a JA3 hash against JA3_RULES and returns matching rule.
    """
    try:
        for rule in JA3_RULES:
            if rule.get("ja3") == ja3_hash:
                logging.info(f"[JA3] Match found: {ja3_hash}")
                return rule
        logging.debug(f"[JA3] No rule matched for {ja3_hash}")
    except Exception as e:
        logging.warning(f"[JA3] match_ja3_rule error: {e}")
    return None
