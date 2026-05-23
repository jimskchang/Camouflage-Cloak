import logging
import random
from ipaddress import ip_address, ip_network
from scapy.all import Ether, IP, TCP, UDP, Raw
from src.settings import get_os_fingerprint
from src.learning_engine import FingerprintLearner

EXCLUDE_SOURCES = [ip_network("192.168.10.0/24")]

# Global cache container hook used internally inside processing nodes
_process_learner_instance = None

def get_shared_learner(shared_proxy=None):
    global _process_learner_instance
    if _process_learner_instance is None:
        _process_learner_instance = FingerprintLearner(shared_map_proxy=shared_proxy)
    return _process_learner_instance

def synthesize_response(pkt, template_bytes, ttl=None, window=None, deceiver=None, shared_proxy=None):
    """
    State-aware response builder configured explicitly for multiprocessing environments.
    """
    try:
        src_ip_str = pkt.l3_field.get("src_IP_str") if hasattr(pkt, 'l3_field') else None
        if src_ip_str and any(ip_address(src_ip_str) in net for net in EXCLUDE_SOURCES):
            return None
            
        # Modest 2% random structural drop pattern for deep fingerprint illusion realism
        if random.random() < 0.02:
            return None

        proto = pkt.l4 if hasattr(pkt, 'l4') else "tcp"
        learner_inst = get_shared_learner(shared_proxy)
        
        # Build network-compliant layer topologies
        base_packet = Ether(src=pkt.l2_field.get('dMAC'), dst=pkt.l2_field.get('sMAC')) / IP(src=pkt.l3_field.get('dest_IP_str'), dst=pkt.l3_field.get('src_IP_str'))
        
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
            
            # Synchronize transaction calculations perfectly with the incoming tracker sequence
            l4_layer.seq = random.randint(10000, 99999)
            l4_layer.ack = (pkt.l4_field.get("seq", 0) + 1) if pkt.l4_field else 0
            l4_layer.flags = "SA" # Default SYN-ACK signature response
            
        elif proto == "udp":
            base_packet = base_packet / UDP()
            l4_layer = base_packet[UDP]
            l4_layer.sport = pkt.l4_field.get('dest_port', 53)
            l4_layer.dport = pkt.l4_field.get('src_port', 53)
            
        if template_bytes:
            base_packet = base_packet / Raw(load=template_bytes)
            
        return bytes(base_packet)
    except Exception as e:
        logging.error(f" ❌ Critical error executing response frame synthesis pipeline: {e}")
        return None
