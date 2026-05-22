import hashlib
import logging
import struct

def gen_key(proto: str, packet: bytes):
    """
    Generate a fingerprint key based on protocol type from raw packet bytes.
    Handles variable-length layer 2 and layer 3 headers dynamically.
    """
    try:
        proto = proto.lower()
        if proto == 'tcp':
            return gen_tcp_key(packet), proto
        elif proto == 'udp':
            return gen_udp_key(packet), proto
        elif proto == 'icmp':
            return gen_icmp_key(packet), proto
        elif proto == 'arp':
            return gen_arp_key(packet), proto
        else:
            return b'', proto
    except Exception as e:
        logging.warning(f"[gen_key] failed for {proto.upper()}: {e}")
        return b'', proto

def normalize_and_hash(fields) -> bytes:
    """
    Normalizes field values safely and returns a SHA-256 hash.
    """
    try:
        byte_fields = []
        for field in fields:
            if isinstance(field, int):
                # Ensure unsigned integer bounds compatibility
                field = min(max(field, 0), 0xFFFFFFFF)
                byte_fields.append(field.to_bytes(4, 'big'))
            elif isinstance(field, str):
                byte_fields.append(field.encode())
            elif isinstance(field, bytes):
                byte_fields.append(field)
            elif field is None:
                byte_fields.append(b'\x00' * 4)
            else:
                logging.debug(f"[normalize_and_hash] Unsupported field type: {type(field)}")
        return hashlib.sha256(b''.join(byte_fields)).digest()
    except Exception as e:
        logging.warning(f"[normalize_and_hash] error: {e}")
        return b''

def _parse_ip_offsets(packet: bytes):
    """
    FIXED: Helper to dynamically compute variable L2 (Ethernet/VLAN) 
    and L3 (IPv4 IHL) boundaries to protect against layer shifting.
    Returns: (l3_start, l4_start, ttl, tos)
    """
    if len(packet) < 14:
        raise ValueError("Frame too short for basic L2 decoding.")
        
    eth_type = struct.unpack("!H", packet[12:14])[0]
    l3_start = 14
    
    # Handle 802.1Q VLAN Tagging layers dynamically
    if eth_type == 0x8100:
        l3_start = 18
        if len(packet) < l3_start + 20:
            raise ValueError("Frame too short for VLAN IP decoding.")
        eth_type = struct.unpack("!H", packet[16:18])[0]
        
    if eth_type != 0x0800:
        # Non-IP traffic fallback (e.g., ARP handling paths)
        return l3_start, None, 0, 0

    # Parse variable IPv4 Internet Header Length (IHL)
    ihl = (packet[l3_start] & 0x0F) * 4
    l4_start = l3_start + ihl
    
    tos = packet[l3_start + 1]
    ttl = packet[l3_start + 8]
    
    return l3_start, l4_start, ttl, tos

def gen_tcp_key(packet: bytes) -> bytes:
    """
    Extracts and normalizes TCP header properties dynamically.
    """
    try:
        _, l4_start, ttl, tos = _parse_ip_offsets(packet)
        if not l4_start or len(packet) < l4_start + 20:
            raise ValueError("Packet truncation encountered during TCP parsing.")
            
        tcp_hdr = packet[l4_start:l4_start + 20]
        src_port, dst_port, seq, ack, offset_flags, win, chk, urg = struct.unpack('!HHLLHHHH', tcp_hdr)
        
        # FIXED: Removed highly volatile metrics (seq, ack, chk) to prevent signature mutations
        fields = [
            ttl, 
            tos, 
            dst_port, 
            offset_flags & 0x0FFF, # Isolate Data Offset & Flags, strip reserved space
            win, 
            urg
        ]
        return normalize_and_hash(fields)
    except Exception as e:
        logging.warning(f"[gen_tcp_key] failed: {e}")
        return b''

def gen_udp_key(packet: bytes) -> bytes:
    """
    Extracts and normalizes UDP header properties dynamically.
    """
    try:
        _, l4_start, ttl, tos = _parse_ip_offsets(packet)
        if not l4_start or len(packet) < l4_start + 8:
            raise ValueError("Packet truncation encountered during UDP parsing.")
            
        udp_hdr = packet[l4_start:l4_start + 8]
        src_port, dst_port, length, checksum = struct.unpack('!HHHH', udp_hdr)
        
        # FIXED: Exclude dynamic payload length/checksum variables if necessary for structural classification
        fields = [ttl, tos, dst_port, length]
        return normalize_and_hash(fields)
    except Exception as e:
        logging.warning(f"[gen_udp_key] failed: {e}")
        return b''

def gen_icmp_key(packet: bytes) -> bytes:
    """
    Extracts and normalizes ICMP header properties dynamically.
    """
    try:
        _, l4_start, ttl, tos = _parse_ip_offsets(packet)
        if not l4_start or len(packet) < l4_start + 8:
            raise ValueError("Packet truncation encountered during ICMP parsing.")
            
        icmp_hdr = packet[l4_start:l4_start + 8]
        icmp_type, code, checksum, ident, seq = struct.unpack('!BBHHH', icmp_hdr)
        
        # Strip fluctuating transactional tracking fields from key maps
        fields = [ttl, tos, icmp_type, code]
        return normalize_and_hash(fields)
    except Exception as e:
        logging.warning(f"[gen_icmp_key] failed: {e}")
        return b''

def gen_arp_key(packet: bytes) -> bytes:
    """
    Extracts and normalizes ARP header fields with variable L2 offset safety.
    """
    try:
        l3_start, _, _, _ = _parse_ip_offsets(packet)
        if len(packet) < l3_start + 28:
            raise ValueError("Packet too short for ARP key extraction.")
            
        arp_hdr = packet[l3_start:l3_start + 28]
        htype, ptype, hlen, plen, op = struct.unpack('!HHBBH', arp_hdr[:8])
        
        fields = [htype, ptype, hlen, plen, op]
        return normalize_and_hash(fields)
    except Exception as e:
        logging.warning(f"[gen_arp_key] failed: {e}")
        return b''
