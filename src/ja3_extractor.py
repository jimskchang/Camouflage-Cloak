# src/ja3_extractor.py

import hashlib
import logging
from scapy.all import TCP
from scapy.layers.tls.all import TLSClientHello, TLS

def extract_ja3(packet_bytes):
    try:
        pkt = TLS(packet_bytes)
        if not pkt.haslayer(TLSClientHello):
            return None

        ch = pkt[TLSClientHello]
        version = ch.version
        ciphers = "-".join(str(c) for c in ch.ciphers)
        extensions = "-".join(str(e.ext_type) for e in ch.ext)
        curves = ""
        point_formats = ""

        for e in ch.ext:
            if hasattr(e, "group_ids"):
                curves = "-".join(str(c) for c in e.group_ids)
            elif hasattr(e, "ec_point_fmt"):
                point_formats = "-".join(str(p) for p in e.ec_point_fmt)

        ja3_str = f"{version},{ciphers},{extensions},{curves},{point_formats}"
        ja3_hash = hashlib.md5(ja3_str.encode()).hexdigest()
        logging.debug(f"[JA3] {ja3_str} → {ja3_hash}")
        return ja3_hash
    except Exception as e:
        logging.debug(f"JA3 extraction failed: {e}")
        return None

def match_ja3_rule(ja3_hash, ja3_rules):
    """
    Match a JA3 hash to configured JA3_RULES.
    Returns the matching rule dict or None.
    """
    for rule in ja3_rules:
        if rule.get("ja3") == ja3_hash:
            return rule
    return None
