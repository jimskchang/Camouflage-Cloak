# src/fingerprint_gen.py

import copy
import logging
import hashlib

def generateKey(packet, proto_type):
    """
    Normalizes the packet structure to generate a deterministic fingerprint key.

    Args:
        packet: A parsed Packet object.
        proto_type: Protocol type ("TCP", "UDP", "ICMP", etc.)

    Returns:
        bytes: Normalized and hashed key.
    """
    try:
        pkt = copy.deepcopy(packet)

        ip_hdr = pkt.l3_field
        tcp_hdr = pkt.l4_field if proto_type == "TCP" else None
        udp_hdr = pkt.l4_field if proto_type == "UDP" else None
        icmp_hdr = pkt.l4_field if proto_type == "ICMP" else None

        fields = []

        # --- IP Header Normalization ---
        if ip_hdr:
            fields.extend([
                ip_hdr.get("version", 4),
                ip_hdr.get("ihl", 5),
                ip_hdr.get("TYPE_OF_SERVICE", 0) & 0xFC,
                0,  # total length
                0,  # ID
                0,  # fragment offset
                ip_hdr.get("ttl", 0) or 0,
                ip_hdr.get("protocol", 0) or 0,
                0,  # checksum
                b"\x00" * 4,
                b"\x00" * 4,
                ip_hdr.get("ip_options", b"") or b""
            ])

        if "vlan" in pkt.l2_field:
            fields.append(pkt.l2_field.get("vlan", 0))

        # --- TCP Header Normalization ---
        if proto_type == "TCP" and tcp_hdr:
            fields.extend([
                0,
                tcp_hdr.get("dest_port", 0) or 0,
                0,
                0,
                0x50,
                tcp_hdr.get("flags", 0) or 0,
                0,
                0,
                0
            ])
            opts = tcp_hdr.get("option_field", {})
            options_filtered = {
                k: v for k, v in opts.items()
                if k not in ["ts_val", "ts_ecr", "sack"] and v is not None
            }
            fields.append(str(sorted(options_filtered.items())).encode())

        # --- UDP Header Normalization ---
        elif proto_type == "UDP" and udp_hdr:
            fields.extend([
                0,
                udp_hdr.get("dest_port", 0) or 0,
                0,
                0
            ])

        # --- ICMP Header Normalization ---
        elif proto_type == "ICMP" and icmp_hdr:
            fields.extend([
                icmp_hdr.get("icmp_type", 0) or 0,
                icmp_hdr.get("code", 0) or 0,
                0,
                0
            ])

        # --- Normalize and Hash ---
        raw_bytes = b"".join(
            x.to_bytes((x.bit_length() + 7) // 8 or 1, 'big') if isinstance(x, int)
            else x if isinstance(x, bytes)
            else str(x).encode() for x in fields
        )

        return hashlib.sha256(raw_bytes).digest()

    except Exception as e:
        logging.warning(f"⚠️ generateKey() failed for {proto_type}: {e}")
        return b''
