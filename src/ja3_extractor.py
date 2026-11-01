import hashlib
import logging
import struct
from typing import Any, Iterable

from src.settings import JA3_RULES


logger = logging.getLogger(__name__)


def _coerce_packet_bytes(packet: Any) -> bytes | None:
    """Normalize packet-like input into raw bytes."""
    if packet is None:
        return None
    if isinstance(packet, (bytes, bytearray, memoryview)):
        return bytes(packet)
    return None


def _parse_ethernet_ipv4(packet: bytes) -> tuple[int, int] | None:
    """
    Return (l3_offset, ip_header_length) for a valid Ethernet + IPv4 packet.
    Supports a single VLAN tag.
    """
    if len(packet) < 14:
        return None

    eth_type = struct.unpack("!H", packet[12:14])[0]
    l3_offset = 14

    if eth_type in (0x8100, 0x88A8):
        if len(packet) < 18:
            return None
        l3_offset = 18
        eth_type = struct.unpack("!H", packet[16:18])[0]

    if eth_type != 0x0800:  # IPv4 only
        return None

    if l3_offset + 20 > len(packet):
        return None

    version_ihl = packet[l3_offset]
    version = version_ihl >> 4
    if version != 4:
        return None

    ip_header_length = (version_ihl & 0x0F) * 4
    if ip_header_length < 20:
        return None

    if l3_offset + ip_header_length > len(packet):
        return None

    protocol = packet[l3_offset + 9]
    if protocol != 6:  # TCP only
        return None

    return l3_offset, ip_header_length


def _parse_tcp_payload(packet: bytes) -> bytes | None:
    """
    Extract the TCP payload for a valid TCP segment.
    Returns None for malformed or non-TCP packets.
    """
    parsed = _parse_ethernet_ipv4(packet)
    if parsed is None:
        return None

    l3_offset, ip_header_length = parsed
    tcp_offset = l3_offset + ip_header_length

    if tcp_offset + 20 > len(packet):
        return None

    data_offset = (packet[tcp_offset + 12] >> 4) * 4
    if data_offset < 20:
        return None

    if tcp_offset + data_offset > len(packet):
        return None

    return packet[tcp_offset + data_offset:]


def _parse_client_hello_fields(tls_payload: bytes) -> tuple[int, list[str], list[str], list[str], list[str]] | None:
    """
    Parse a TLS ClientHello payload and return:
    (handshake_version, ciphers, extensions, curves, ec_point_formats)
    """
    if len(tls_payload) < 48:
        return None

    if tls_payload[0] != 0x16 or tls_payload[5] != 0x01:
        return None

    handshake_version = struct.unpack("!H", tls_payload[9:11])[0]

    session_id_len = tls_payload[43]
    index = 44 + session_id_len
    if index + 2 > len(tls_payload):
        return None

    # Cipher suites
    cipher_len = struct.unpack("!H", tls_payload[index:index + 2])[0]
    index += 2

    ciphers: list[str] = []
    for _ in range(cipher_len // 2):
        if index + 2 > len(tls_payload):
            return None
        cipher_value = struct.unpack("!H", tls_payload[index:index + 2])[0]
        ciphers.append(str(cipher_value))
        index += 2

    # Compression methods
    if index + 1 > len(tls_payload):
        return None
    compression_methods_len = tls_payload[index]
    index += 1

    if index + compression_methods_len > len(tls_payload):
        return None
    index += compression_methods_len

    # Extensions
    if index + 2 > len(tls_payload):
        return None
    ext_total_len = struct.unpack("!H", tls_payload[index:index + 2])[0]
    index += 2

    ext_end = index + ext_total_len
    if ext_end > len(tls_payload):
        return None

    extensions: list[str] = []
    curves: list[str] = []
    ec_points: list[str] = []

    while index + 4 <= ext_end:
        if index + 4 > len(tls_payload):
            return None

        ext_type = struct.unpack("!H", tls_payload[index:index + 2])[0]
        ext_len = struct.unpack("!H", tls_payload[index + 2:index + 4])[0]
        index += 4

        if index + ext_len > len(tls_payload):
            return None

        ext_data = tls_payload[index:index + ext_len]
        index += ext_len

        extensions.append(str(ext_type))

        if ext_type == 0x000A and len(ext_data) >= 2:
            curve_len = struct.unpack("!H", ext_data[:2])[0]
            offset = 2
            while offset + 2 <= min(len(ext_data), 2 + curve_len):
                curve_value = struct.unpack("!H", ext_data[offset:offset + 2])[0]
                curves.append(str(curve_value))
                offset += 2

        elif ext_type == 0x000B and len(ext_data) >= 1:
            format_count = ext_data[0]
            point_formats = ext_data[1:1 + format_count]
            ec_points.extend(str(b) for b in point_formats)

    ja3_fields = (
        handshake_version,
        ciphers,
        extensions,
        curves,
        ec_points,
    )
    return ja3_fields


def extract_ja3(packet_bytes: Any) -> str | None:
    """
    Extract a JA3 fingerprint from a raw Ethernet/TCP packet.

    Returns:
        MD5 JA3 hash string, or None when the packet is malformed or not a TLS ClientHello.
    """
    packet = _coerce_packet_bytes(packet_bytes)
    if packet is None or len(packet) < 60:
        return None

    tcp_payload = _parse_tcp_payload(packet)
    if tcp_payload is None:
        return None

    parsed = _parse_client_hello_fields(tcp_payload)
    if parsed is None:
        return None

    handshake_version, ciphers, extensions, curves, ec_points = parsed
    ja3_string = (
        f"{handshake_version},"
        f"{'-'.join(ciphers)},"
        f"{'-'.join(extensions)},"
        f"{'-'.join(curves)},"
        f"{'-'.join(ec_points)}"
    )

    ja3_hash = hashlib.md5(ja3_string.encode("utf-8")).hexdigest()
    logger.debug("JA3 constructed signature: %s -> %s", ja3_string, ja3_hash)
    return ja3_hash


def extract_ja3_from_packet(pkt: Any) -> str | None:
    """
    Convenience wrapper for packet objects exposing a `.packet` attribute.
    """
    try:
        if pkt is None:
            return None
        packet = getattr(pkt, "packet", pkt)
        if packet is None:
            return None
        return extract_ja3(packet)
    except Exception:
        logger.exception("JA3 extraction failed for packet object")
        return None


def match_ja3_rule(ja3_hash: str | None) -> dict | None:
    """
    Return the configured matching rule for a JA3 hash, if any.
    """
    if not ja3_hash:
        return None

    normalized_hash = str(ja3_hash).strip()
    for rule in JA3_RULES:
        if rule.get("ja3") == normalized_hash:
            logger.info("JA3 rule matched: %s", normalized_hash)
            return rule

    logger.debug("No JA3 rule matched for: %s", normalized_hash)
    return None


__all__ = [
    "extract_ja3",
    "extract_ja3_from_packet",
    "match_ja3_rule",
]
