# src/ja3_extractor.py

import hashlib
import logging
from collections import namedtuple

try:
    from scapy.all import TLSClientHello, TLS_Ext_ServerName, TCP
except ImportError:
    TLSClientHello = None
    TLS_Ext_ServerName = None
    TCP = None

# --- JA3 Parser Core ---

def extract_ja3_from_packet(pkt_bytes: bytes) -> str:
    """
    Extracts a JA3 fingerprint hash from a TCP packet containing a TLS Client Hello.
    Returns the JA3 hash string or None.
    """
    try:
        from scapy.layers.tls.all import TLS
        pkt = TLS(pkt_bytes)
        if not pkt.haslayer("TLSClientHello"):
            return None

        ch = pkt.getlayer("TLSClientHello")
        version = str(ch.version)
        cipher_suites = "-".join(str(cs) for cs in ch.ciphers)
        extensions = "-".join(str(ext.type) for ext in ch.ext)
        elliptic_curves = "-".join(str(e) for e in getattr(ch, 'elliptic_curves', []))
        ec_point_formats = "-".join(str(e) for e in getattr(ch, 'ec_point_formats', []))

        ja3_string = ",".join([
            version,
            cipher_suites,
            extensions,
            elliptic_curves,
            ec_point_formats
        ])
        ja3_hash = hashlib.md5(ja3_string.encode()).hexdigest()
        return ja3_hash

    except Exception as e:
        logging.debug(f"[JA3] Failed to extract JA3: {e}")
        return None

# --- JA3 Rule Matching ---

def match_ja3_rule(ja3_hash: str, ja3_rules: list) -> dict:
    """
    Match the given JA3 hash against JA3_RULES list.
    Returns matching rule or None.
    """
    for rule in ja3_rules:
        if rule.get("ja3") == ja3_hash:
            return rule
    return None
