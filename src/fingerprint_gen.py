# src/fingerprint_gen.py

import copy
import logging
import hashlib
from scapy.all import DNS, Raw

def generateKey(packet, proto_type, use_hash=True):
    """
    Generate a normalized fingerprint key from a parsed Packet object.

    Args:
        packet: A Packet object with .ip, .tcp, .udp, .icmp, .raw, etc.
        proto_type (str): "TCP", "UDP", "ICMP", "ARP", etc.
        use_hash (bool): If True, return SHA256(key), else raw bytes.

    Returns:
        bytes: A normalized key (SHA256 digest or raw fingerprint bytes).
    """
    try:
        pkt = copy.deepcopy(packet)

        # Normalize IP layer
        if hasattr(pkt, 'ip') and pkt.ip:
            pkt.ip.ttl = 0
            pkt.ip.id = 0
            pkt.ip.chksum = 0
            pkt.ip.len = 0
            pkt.ip.frag = 0
            pkt.ip.flags = 0
            pkt.ip.tos = 0
            if hasattr(pkt.ip, 'options'):
                pkt.ip.options = b''

        # Normalize VLAN if present
        if hasattr(pkt, 'dot1q') and pkt.dot1q:
            pkt.dot1q.vlan = 0
            pkt.dot1q.prio = 0
            pkt.dot1q.id = 0

        # TCP-specific normalization
        if proto_type == "TCP" and hasattr(pkt, 'tcp') and pkt.tcp:
            pkt.tcp.seq = 0
            pkt.tcp.ack = 0
            pkt.tcp.window = 0
            pkt.tcp.chksum = 0
            pkt.tcp.urgptr = 0
            pkt.tcp.dataofs = 0
            pkt.tcp.options = [opt for opt in pkt.tcp.options if opt[0] not in ("Timestamp", "SACK")]

        # UDP-specific normalization
        elif proto_type == "UDP" and hasattr(pkt, 'udp') and pkt.udp:
            pkt.udp.len = 0
            pkt.udp.chksum = 0

        # ICMP-specific normalization
        elif proto_type == "ICMP" and hasattr(pkt, 'icmp') and pkt.icmp:
            pkt.icmp.chksum = 0
            pkt.icmp.seq = 0
            pkt.icmp.id = 0

        # L7 Application layer (Raw/DNS/HTTP)
        l7_id = b''
        if hasattr(pkt, 'dns') and pkt.dns:
            l7_id = bytes(pkt.dns.qd.qname) if pkt.dns.qd else b'dns'
        elif hasattr(pkt, 'raw') and pkt.raw:
            raw_payload = pkt.raw.load.lower()
            if b"http" in raw_payload:
                l7_id = b'http'
            elif b"smb" in raw_payload:
                l7_id = b'smb'
            elif b"ftp" in raw_payload:
                l7_id = b'ftp'
            elif b"ssh" in raw_payload:
                l7_id = b'ssh'
            elif b"sip" in raw_payload:
                l7_id = b'sip'

        # Final byte blob
        raw_bytes = bytes(pkt.packet) + l7_id

        if use_hash:
            return hashlib.sha256(raw_bytes).digest()
        return raw_bytes

    except Exception as e:
        logging.warning(f"⚠️ generateKey failed for {proto_type}: {e}")
        return b''
