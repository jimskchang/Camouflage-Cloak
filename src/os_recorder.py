# src/os_recorder.py
import logging
from collections import defaultdict
from src.fingerprint_utils import generateKey

def templateSynthesis(packet, proto_type, template_dict, pair_dict, host_ip):
    """
    Build OS fingerprint templates from observed packets using normalized request/response pairs.

    Args:
        packet: parsed Packet object with l3_field/l4_field attributes.
        proto_type: 'TCP', 'UDP', 'ICMP', or 'ARP'
        template_dict: dict of {proto_type: {normalized_key: response_packet}}
        pair_dict: dict mapping request tuple to normalized key
        host_ip: string, local protected host IP (e.g. '192.168.1.10')

    Returns:
        Updated template_dict with synthesized fingerprint entries.
    """
    try:
        src_ip = packet.l3_field.get("src_IP_str")
        dst_ip = packet.l3_field.get("dest_IP_str")
        src_port = packet.l4_field.get("src_port")
        dst_port = packet.l4_field.get("dest_port")

        # Define pair based on protocol type
        if proto_type == "TCP":
            pair = (src_ip, dst_ip, src_port, dst_port)
        elif proto_type == "ICMP":
            pair = packet.l4_field.get("icmp_id", 0)
        elif proto_type == "ARP":
            pair = (src_ip, dst_ip)
        elif proto_type == "UDP":
            pair = (src_ip, dst_ip, src_port, dst_port)
        else:
            return template_dict

        # Incoming request packet
        if dst_ip == host_ip:
            key = generateKey(packet, proto_type)
            pair_dict[pair] = key
            if key not in template_dict[proto_type]:
                template_dict[proto_type][key] = None

        # Outgoing response packet
        elif src_ip == host_ip and pair in pair_dict:
            if proto_type == "ICMP" and packet.l4_field.get("icmp_type") == 3:
                key = generateKey(packet, "UDP")
                if key not in template_dict["UDP"]:
                    template_dict["UDP"][key] = None
            else:
                key = pair_dict[pair]
                template_dict[proto_type][key] = packet.packet

        return template_dict

    except Exception as e:
        logging.warning(f"⚠️ templateSynthesis error: {e}")
        return template_dict
