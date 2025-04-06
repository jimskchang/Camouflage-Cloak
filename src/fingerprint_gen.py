# src/fingerprint_gen.py
import copy
import logging

def generateKey(packet, proto_type):
    """
    Generates a normalized fingerprint key from a Packet object.
    Normalization includes removing variable fields (e.g., TTL, ID, checksums).
    """
    try:
        pkt = copy.deepcopy(packet)

        # Normalize IP
        if hasattr(pkt, 'ip') and pkt.ip:
            pkt.ip.ttl = 0
            pkt.ip.id = 0
            pkt.ip.chksum = 0

        # Normalize TCP
        if proto_type == 'TCP' and hasattr(pkt, 'tcp') and pkt.tcp:
            pkt.tcp.seq = 0
            pkt.tcp.ack = 0
            pkt.tcp.window = 0
            pkt.tcp.chksum = 0
            pkt.tcp.urgptr = 0
            pkt.tcp.options = [opt for opt in pkt.tcp.options if opt[0] not in ('Timestamp', 'SACK')]

        # Normalize UDP
        elif proto_type == 'UDP' and hasattr(pkt, 'udp') and pkt.udp:
            pkt.udp.len = 0
            pkt.udp.chksum = 0

        # Normalize ICMP
        elif proto_type == 'ICMP' and hasattr(pkt, 'icmp') and pkt.icmp:
            pkt.icmp.chksum = 0
            pkt.icmp.id = 0
            pkt.icmp.seq = 0

        # Return normalized bytes as key
        return pkt.get_signature(proto_type)

    except Exception as e:
        logging.warning(f"\u26a0 generateKey failed for {proto_type}: {e}")
        return b''
