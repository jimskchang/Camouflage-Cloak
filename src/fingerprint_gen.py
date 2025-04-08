# src/fingerprint_gen.py

import copy
import hashlib
import logging
from scapy.all import DNS, DNSQR, Raw

def generateKey(packet, proto_type, enable_l7=True, use_hash=True):
    """
    Generate a normalized key based on L3/L4 (and optionally L7) fields.

    Args:
        packet: Parsed Packet object
        proto_type: "TCP", "UDP", "ICMP", "ARP"
        enable_l7 (bool): include DNS/HTTP fields
        use_hash (bool): return SHA256 of key

    Returns:
        bytes: raw or hashed key
    """
    try:
        pkt = copy.deepcopy(packet)
        fields = []

        ip = pkt.l3_field
        l4 = pkt.l4_field

        # --- IP Header Normalization ---
        if ip:
            fields.extend([
                ip.get("version", 4),
                ip.get("ihl", 5),
                ip.get("TYPE_OF_SERVICE", 0) & 0xFC,
                0,  # total_length
                0,  # ID
                0,  # frag offset
                ip.get("ttl", 0),
                ip.get("protocol", 0),
                0,
                b"\x00" * 4,
                b"\x00" * 4,
            ])
            if "ip_options" in ip:
                fields.append(ip["ip_options"])

        if "vlan" in pkt.l2_field:
            fields.append(pkt.l2_field["vlan"])

        # --- TCP ---
        if proto_type == "TCP":
            fields.extend([
                0,
                l4.get("dest_port", 0),
                0, 0,
                0x50,
                l4.get("flags", 0),
                0, 0, 0
            ])
            opts = l4.get("option_field", {})
            stripped = {
                k: v for k, v in opts.items() if k not in ["ts_val", "ts_ecr", "sack"]
            }
            fields.append(str(sorted(stripped.items())).encode())

        # --- UDP ---
        elif proto_type == "UDP":
            fields.extend([
                0,
                l4.get("dest_port", 0),
                0, 0
            ])

        # --- ICMP ---
        elif proto_type == "ICMP":
            fields.extend([
                l4.get("icmp_type", 0),
                l4.get("code", 0),
                0, 0
            ])

        # --- L7 Fingerprint (DNS, HTTP) ---
        if enable_l7 and hasattr(pkt, "packet"):
            try:
                payload = pkt.packet[54:]  # offset past typical IP+TCP
                if proto_type == "UDP" and l4.get("dest_port") == 53:
                    dns = DNS(payload)
                    if dns and dns.qr == 0:
                        for i in range(min(2, dns.qdcount)):
                            q = dns[DNSQR][i]
                            fields.append(q.qname)
                            fields.append(q.qtype.to_bytes(1, "big"))
                elif proto_type == "TCP" and l4.get("dest_port") in [80, 443]:
                    http = Raw(payload).load.decode(errors="ignore")
                    lines = http.split("\r\n")
                    for line in lines[:3]:  # first few header lines
                        fields.append(line.strip().lower().encode())
            except Exception as e:
                logging.debug(f"⚠️ L7 parsing skipped: {e}")

        # Convert all to bytes
        raw = b"".join(
            x.to_bytes(1, "big") if isinstance(x, int) else x for x in fields
        )

        return hashlib.sha256(raw).digest() if use_hash else raw

    except Exception as e:
        logging.warning(f"⚠️ generateKey failed for {proto_type}: {e}")
        return b""
