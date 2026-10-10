"""Network packet response synthesis with multiprocessing-safe learner.

Refactored to accept SharedState for unified fingerprint learning across worker processes.
"""

import logging
import random
import threading
from ipaddress import ip_address, ip_network
from scapy.all import Ether, IP, TCP, UDP, Raw
from src.settings import get_os_fingerprint
from src.learning_engine import FingerprintLearner

EXCLUDE_SOURCES = [ip_network("192.168.10.0/24")]

# Global cache container hook used internally inside processing nodes
# Per-process singleton (threading.Lock is fine here; this is within a single process)
_process_learner_instance = None
_learner_lock = threading.Lock()  # Per-process lock for singleton initialization


def get_shared_learner(shared_state):
    """Thread-safe lazy initialization of learner instance per worker process.
    
    Each process gets one learner instance; manager proxies handle cross-process sync.
    Uses double-checked lock pattern to minimize lock contention.
    
    Args:
        shared_state: SharedState instance containing fingerprint_map and fingerprint_lock
    
    Returns:
        FingerprintLearner instance
    """
    global _process_learner_instance
    
    # === First check (no lock) - fast path ===
    if _process_learner_instance is not None:
        return _process_learner_instance
    
    # === Acquire lock for initialization ===
    with _learner_lock:
        # === Second check (with lock) - ensure another thread didn't initialize ===
        if _process_learner_instance is None:
            _process_learner_instance = FingerprintLearner(
                shared_map_proxy=shared_state.fingerprint_map,
                shared_lock=shared_state.fingerprint_lock
            )
            logging.info(
                "✅ FingerprintLearner initialized with shared_state in worker process"
            )
    
    return _process_learner_instance


def synthesize_response(pkt, template_bytes, ttl=None, window=None, deceiver=None, shared_state=None):
    """State-aware response builder configured for multiprocessing environments.
    
    Args:
        pkt: Packet object to respond to
        template_bytes: Template bytes for response (or None for default)
        ttl: TTL value (optional)
        window: TCP window size (optional)
        deceiver: PortDeceiver instance (optional, for OS config)
        shared_state: SharedState instance (optional, for learner access)
    
    Returns:
        bytes: Synthesized response packet, or None on error
    """
    try:
        src_ip_str = pkt.l3_field.get("src_IP_str") if hasattr(pkt, 'l3_field') else None
        if src_ip_str and any(ip_address(src_ip_str) in net for net in EXCLUDE_SOURCES):
            return None
            
        # Modest 2% random structural drop pattern for deep fingerprint illusion realism
        if random.random() < 0.02:
            return None

        proto = pkt.l4 if hasattr(pkt, 'l4') else "tcp"
        
        # === Get learner with shared_state ===
        if shared_state is not None:
            learner_inst = get_shared_learner(shared_state)
        
        # Build network-compliant layer topologies
        base_packet = Ether(src=pkt.l2_field.get('dMAC'), dst=pkt.l2_field.get('sMAC')) / IP(
            src=pkt.l3_field.get('dest_IP_str'), 
            dst=pkt.l3_field.get('src_IP_str')
        )
        
        if proto == "tcp":
            base_packet = base_packet / TCP()
            l4_layer = base_packet[TCP]
            
            if deceiver and hasattr(deceiver, 'os_name'):
                os_config = get_os_fingerprint(deceiver.os_name)
                if "tcp_options" in os_config:
                    l4_layer.options = os_config["tcp_options"]
                if "window" in os_config:
                    l4_layer.window = os_config["window"]
            
            if window:
                l4_layer.window = window
                
            l4_layer.sport = pkt.l4_field.get('dest_port', 80)
            l4_layer.dport = pkt.l4_field.get('src_port', 12345)
            
            # Synchronize transaction calculations with incoming sequence
            l4_layer.seq = random.randint(10000, 99999)
            l4_layer.ack = (pkt.l4_field.get("seq", 0) + 1) if pkt.l4_field else 0
            l4_layer.flags = "SA"  # Default SYN-ACK response
            
        elif proto == "udp":
            base_packet = base_packet / UDP()
            l4_layer = base_packet[UDP]
            l4_layer.sport = pkt.l4_field.get('dest_port', 53)
            l4_layer.dport = pkt.l4_field.get('src_port', 53)
            
        if template_bytes:
            base_packet = base_packet / Raw(load=template_bytes)
            
        return bytes(base_packet)
    except Exception as e:
        logging.error(f"❌ Critical error in response synthesis pipeline: {e}")
        return None
