import logging
from collections import defaultdict

def templateSynthesis(packet, proto_type, template_dict, pair_dict, host_ip):
    """
    Build OS fingerprint templates from observed packets using normalized request/response pairs.
    """
    try:
        src_ip = packet.l3_field.get("src_IP_str")
        dst_ip = packet.l3_field.get("dest_IP_str")
        src_port = packet.l4_field.get("src_port")
        dst_port = packet.l4_field.get("dest_port")

        # Define the unique pair based on protocol
        if proto_type == "TCP":
            pair = (src_ip, dst_ip, src_port, dst_port)
        elif proto_type == "UDP":
            pair = (src_ip, dst_ip, src_port, dst_port)
        elif proto_type == "ICMP":
            pair = packet.l4_field.get("icmp_id", 0)
        elif proto_type == "ARP":
            pair = (src_ip, dst_ip)
        else:
            logging.debug(f"[templateSynthesis] Unsupported proto_type: {proto_type}")
            return template_dict

        # Incoming request → generate signature
        if dst_ip == host_ip:
            try:
                key = packet.get_signature(proto_type)
                pair_dict[pair] = key
                if key not in template_dict[proto_type]:
                    template_dict[proto_type][key] = None
            except Exception as e:
                logging.warning(f"[Packet] Failed to get signature for {proto_type}: {e}")

        # Outgoing response → map to stored key
        elif src_ip == host_ip and pair in pair_dict:
            try:
                if proto_type == "ICMP" and packet.l4_field.get("icmp_type") == 3:
                    key = packet.get_signature("UDP")
                    if key not in template_dict["UDP"]:
                        template_dict["UDP"][key] = None
                else:
                    key = pair_dict[pair]
                    template_dict[proto_type][key] = packet.packet
            except Exception as e:
                logging.warning(f"[Packet] Response mapping failed for {proto_type}: {e}")

        return template_dict

    except Exception as e:
        logging.warning(f"⚠️ templateSynthesis general error: {e}")
        return template_dict
