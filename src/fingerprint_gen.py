# src/fingerprint_gen.py

import copy
import logging

def generateKey(packet, proto_type):
    """
    Normalizes the packet structure to generate a deterministic key.

    Args:
        packet: A parsed Packet object with l2/l3/l4 fields.
        proto_type: One of "TCP", "UDP", "ICMP", "ARP", etc.

    Returns:
        bytes: A normalized byte-string representing the fingerprintable part of the packet.
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
                ip_hdr.get("TYPE_OF_SERVICE", 0) & 0xFC,  # DSCP bits only
                0,  # total length (normalized)
                0,  # ID
                0,  # fragment offset
                ip_hdr.get("ttl", 0),
                ip_hdr.get("protocol", 0),
                0,  # checksum
                b"\x00" * 4,  # src IP
                b"\x00" * 4   # dst IP
            ])

        # --- VLAN / IP Options (Hook) ---
        if "vlan" in pkt.l2_field:
            fields.append(pkt.l2_field["vlan"])
        if ip_hdr and "ip_options" in ip_hdr:
            fields.append(ip_hdr["ip_options"])

        # --- TCP Header Normalization ---
        if proto_type == "TCP" and tcp_hdr:
            fields.extend([
                0,  # src_port
                tcp_hdr.get("dest_port", 0),
                0,  # seq
                0,  # ack
                0x50,  # data offset
                tcp_hdr.get("flags", 0),
                0,  # window
                0,  # checksum
                0   # urgent pointer
            ])
            opts = tcp_hdr.get("option_field", {})
            options_filtered = {
                k: v for k, v in opts.items()
                if k not in ["ts_val", "ts_ecr", "sack"]
            }
            fields.append(str(sorted(options_filtered.items())).encode())

        # --- UDP Header Normalization ---
        elif proto_type == "UDP" and udp_hdr:
            fields.extend([
                0,  # src_port
                udp_hdr.get("dest_port", 0),
                0,  # length
                0   # checksum
            ])

        # --- ICMP Header Normalization ---
        elif proto_type == "ICMP" and icmp_hdr:
            fields.extend([
                icmp_hdr.get("icmp_type", 0),
                icmp_hdr.get("code", 0),
                0, 0  # checksum, id
            ])

        # Return raw bytes
        raw_bytes = b"".join(
            x.to_bytes(1, 'big') if isinstance(x, int) else x
            for x in fields
        )
        return raw_bytes

    except Exception as e:
        logging.warning(f"⚠️ generateKey() failed for {proto_type}: {e}")
        return b''
