import logging
import hashlib
import struct

def generateKey(packet, proto_type):
    """
    Normalizes a parsed Packet object into a deterministic fingerprint key.

    Args:
        packet: Packet instance with unpacked fields.
        proto_type: Protocol type ("TCP", "UDP", "ICMP", etc.)

    Returns:
        bytes: SHA-256 hash of normalized protocol-specific fields.
    """
    try:
        ip_hdr = packet.l3_field
        tcp_hdr = packet.l4_field if proto_type == "TCP" else None
        udp_hdr = packet.l4_field if proto_type == "UDP" else None
        icmp_hdr = packet.l4_field if proto_type == "ICMP" else None

        chunks = []

        # --- IP Header Normalization ---
        if ip_hdr:
            # Struct Format: B (Version/IHL combined or solo), B (TOS), H (TTL/Proto split setup)
            # Standardize sizes to mirror exact RFC protocol layouts
            version = ip_hdr.get("version", 4)
            ihl = ip_hdr.get("ihl", 5)
            tos = ip_hdr.get("TYPE_OF_SERVICE", 0) & 0xFC
            ttl = ip_hdr.get("ttl", 0)
            protocol = ip_hdr.get("protocol", 0)
            
            chunks.append(struct.pack("!BBBB", (version << 4) | ihl, tos, ttl, protocol))
            chunks.append(ip_hdr.get("ip_options", b""))

        # --- VLAN Profile Tagging ---
        if "vlan" in packet.l2_field:
            chunks.append(struct.pack("!H", packet.l2_field.get("vlan", 0)))

        # --- TCP Protocol Matching ---
        if proto_type == "TCP" and tcp_hdr:
            dest_port = tcp_hdr.get("dest_port", 0)
            flags = tcp_hdr.get("flags", 0)
            
            # Mask volatile sequence numbers and source ports
            chunks.append(struct.pack("!HH", 0, dest_port)) # Ports
            chunks.append(struct.pack("!II", 0, 0))         # Seq / Ack
            chunks.append(struct.pack("!BB", 0x50, flags))  # Data Offset / Flags
            chunks.append(struct.pack("!HHH", 0, 0, 0))     # Window / Checksum / Urg
            
            # Options sanitization
            opts = tcp_hdr.get("option_field", {})
            filtered_opts = {
                k: v for k, v in opts.items()
                if k not in ["ts_val", "ts_ecr", "sack"] and v is not None
            }
            # Maintain strict string sort configurations before hashing conversion
            chunks.append(str(sorted(filtered_opts.items())).encode())

        # --- UDP Protocol Matching ---
        elif proto_type == "UDP" and udp_hdr:
            dest_port = udp_hdr.get("dest_port", 0)
            chunks.append(struct.pack("!HH", 0, dest_port))

        # --- ICMP Protocol Matching ---
        elif proto_type == "ICMP" and icmp_hdr:
            icmp_type = icmp_hdr.get("icmp_type", 0)
            code = icmp_hdr.get("code", 0)
            chunks.append(struct.pack("!BB", icmp_type, code))

        # --- Final Stream Consolidation and Hashing ---
        raw_bytes = b"".join(chunks)
        return hashlib.sha256(raw_bytes).digest()

    except Exception as e:
        logging.warning(f"⚠️ generateKey() failed for {proto_type}: {e}")
        return b''

# Alias definition for backwards compatibility matching across scripts
gen_key = generateKey
