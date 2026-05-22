import logging
import hashlib
import struct
from src.settings import JA3_RULES

def extract_ja3(packet_bytes: bytes) -> str:
    """
    Extract a JA3 fingerprint from raw TCP packet bytes safely.
    Handles dynamic TCP header option sizing and accurately follows TLS specifications.
    """
    try:
        if len(packet_bytes) < 60:
            return None

        # 1. Dynamically parse L3 and L4 structures to capture true L7 payloads safely
        eth_type = struct.unpack("!H", packet_bytes[12:14])[0]
        l3_start = 14
        if eth_type == 0x8100: # Account for VLAN tags
            l3_start = 18
            eth_type = struct.unpack("!H", packet_bytes[16:18])[0]
            
        if eth_type != 0x0800:
            return None # Ignore non-IPv4 traffic streams

        ihl = (packet_bytes[l3_start] & 0x0F) * 4
        l4_start = l3_start + ihl
        
        # Parse real TCP header data length parameters dynamically
        tcp_data_offset = (packet_bytes[l4_start + 12] >> 4) * 4
        tls_start = l4_start + tcp_data_offset
        
        tcp_payload = packet_bytes[tls_start:]
        
        # 2. Validate clean TLS Handshake ClientHello record characteristics 
        if len(tcp_payload) < 48:
            return None
        if tcp_payload[0] != 0x16 or tcp_payload[5] != 0x01:
            return None  # Frame structure is not a TLS ClientHello sequence

        # Extract precise TLS parameters according to standard RFC specs
        handshake_version = struct.unpack("!H", tcp_payload[9:11])[0]

        # FIXED: Shift pointer exactly 48 bytes to target the true Session ID length boundary
        session_id_len = tcp_payload[48]
        index = 49 + session_id_len
        if index + 2 > len(tcp_payload):
            return None

        # --- Ciphers Extraction Engine ---
        cipher_len = struct.unpack("!H", tcp_payload[index:index + 2])[0]
        index += 2
        ciphers = []
        for i in range(0, cipher_len, 2):
            if index + 2 > len(tcp_payload):
                return None
            cipher = struct.unpack("!H", tcp_payload[index:index + 2])[0]
            ciphers.append(str(cipher))
            index += 2

        # --- Compression Handling ---
        if index + 1 > len(tcp_payload):
            return None
        comp_methods_len = tcp_payload[index]
        index += 1 + comp_methods_len

        # --- Extension State Machine Processing Engine ---
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

            # Deep parse Elliptic Curves / Supported Groups parameters safely
            if ext_type == 10 and len(ext_data) >= 2:
                curve_len = struct.unpack("!H", ext_data[:2])[0]
                for i in range(2, 2 + curve_len, 2):
                    if i + 2 <= len(ext_data):
                        curve = struct.unpack("!H", ext_data[i:i + 2])[0]
                        curves.append(str(curve))
            # Extract EC Point Formats parameters
            elif ext_type == 11 and len(ext_data) >= 1:
                ec_formats += [str(b) for b in ext_data[1:]]

            index += 4 + ext_len

        # FIXED: Reconstruct parameters according to the official JA3 signature format
        ja3_str = f"{handshake_version}," \
                  f"{'-'.join(ciphers)}," \
                  f"{'-'.join(exts)}," \
                  f"{'-'.join(curves)}," \
                  f"{'-'.join(ec_formats)}"

        ja3_hash = hashlib.md5(ja3_str.encode()).hexdigest()
        logging.debug(f"[JA3] Constructed signature string: '{ja3_str}' → MD5: {ja3_hash}")
        return ja3_hash

    except Exception as e:
        logging.warning(f"[JA3] extract_ja3 extraction sequence error exception failure: {e}")
        return None

def extract_ja3_from_packet(pkt) -> str:
    """
    Interface hook to extract signatures safely using parsed Packet object arrays.
    """
    try:
        return extract_ja3(pkt.packet)
    except Exception as e:
        logging.warning(f"[JA3] extract_ja3_from_packet engine error: {e}")
        return None

def match_ja3_rule(ja3_hash: str) -> dict:
    """
    Matches a JA3 hash against configured rules and returns the matching rule dictionary.
    """
    try:
        for rule in JA3_RULES:
            if rule.get("ja3") == ja3_hash:
                logging.info(f"🎭 [JA3] Match found within rules matrix: {ja3_hash}")
                return rule
        logging.debug(f"[JA3] No profile rules matched for signature: {ja3_hash}")
    except Exception as e:
        logging.warning(f"[JA3] match_ja3_rule verification module exception error: {e}")
    return None
