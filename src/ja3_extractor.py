# src/ja3_extractor.py

import hashlib
import struct
import logging


def extract_ja3(packet_bytes: bytes) -> str:
    """
    Extracts a JA3 fingerprint from raw TCP packet bytes (typically for port 443).
    This is a simplified version assuming TLS ClientHello is directly available.

    Returns:
        ja3_string: Comma-separated JA3 string
    """
    try:
        # Search for TLS handshake
        if len(packet_bytes) < 54:
            return None

        tcp_payload = packet_bytes[54:]
        if tcp_payload[0] != 0x16:  # Not a TLS Handshake
            return None

        # TLS Version
        version = struct.unpack("!H", tcp_payload[1:3])[0]

        # Lengths
        handshake_type = tcp_payload[5]
        if handshake_type != 0x01:
            return None  # Not a ClientHello

        session_id_len = tcp_payload[43]
        index = 44 + session_id_len

        # Cipher Suites
        cipher_len = struct.unpack("!H", tcp_payload[index:index + 2])[0]
        index += 2
        ciphers = []
        for i in range(0, cipher_len, 2):
            cipher = struct.unpack("!H", tcp_payload[index + i:index + i + 2])[0]
            ciphers.append(str(cipher))
        index += cipher_len

        # Compression methods
        comp_methods_len = tcp_payload[index]
        index += 1 + comp_methods_len

        # Extensions
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

        return ja3_str

    except Exception as e:
        logging.warning(f"[JA3] Failed to extract JA3: {e}")
        return None


def match_ja3_rule(ja3_string: str, rule_set: list) -> dict:
    """
    Looks for a JA3 string match in the given JA3_RULES.

    Args:
        ja3_string: The raw JA3 string (not the MD5 hash).
        rule_set: List of JA3 rules from settings.JA3_RULES.

    Returns:
        dict: The matched rule dictionary or None.
    """
    try:
        for rule in rule_set:
            if rule.get("ja3") == ja3_string:
                return rule
    except Exception as e:
        logging.warning(f"[JA3] match_ja3_rule error: {e}")
    return None
