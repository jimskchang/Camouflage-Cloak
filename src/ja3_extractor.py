# src/ja3_extractor.py

import hashlib
import logging
from scapy.all import TCP, Raw
from scapy.layers.inet import IP
from scapy.layers.tls.record import TLS
from scapy.layers.tls.handshake import TLSClientHello

def extract_ja3_from_packet(pkt) -> str:
    """
    Extract JA3 fingerprint from a TLS ClientHello packet.

    Args:
        pkt: A Scapy packet (must contain TCP and Raw layers)

    Returns:
        str: The JA3 hash as a hex string, or None if not a TLS ClientHello
    """
    try:
        if not pkt.haslayer(TCP) or not pkt.haslayer(Raw):
            return None

        tcp_payload = bytes(pkt[Raw].load)
        tls = TLS(tcp_payload)
        if not tls or not tls.msg or not isinstance(tls.msg[0], TLSClientHello):
            return None

        ch = tls.msg[0]

        # JA3 Format: Version,CipherSuites,Extensions,EllipticCurves,EllipticCurvePointFormats
        version = str(ch.version)
        ciphers = "-".join(str(c) for c in ch.ciphers)
        exts = "-".join(str(e.ext_type) for e in ch.ext if hasattr(e, 'ext_type'))

        curves = []
        ec_formats = []
        for e in ch.ext:
            if hasattr(e, "group_ids"):  # SupportedGroups / EllipticCurves
                curves = e.group_ids
            elif hasattr(e, "ecpl"):  # EC Point Formats
                ec_formats = list(e.ecpl)

        curves_str = "-".join(str(x) for x in curves)
        ecf_str = "-".join(str(x) for x in ec_formats)

        ja3_str = ",".join([version, ciphers, exts, curves_str, ecf_str])
        ja3_hash = hashlib.md5(ja3_str.encode()).hexdigest()

        logging.debug(f"🔎 JA3: {ja3_str} → {ja3_hash}")
        return ja3_hash

    except Exception as e:
        logging.debug(f"❌ JA3 extraction failed: {e}")
        return None
