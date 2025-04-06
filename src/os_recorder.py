# src/os_recorder.py
import logging
from datetime import datetime

def templateSynthesis(packet, proto_type, template_dict, pair_dict, host_ip):
    """
    Enhanced template synthesis with full debug logging:
    key, TTL, window, options, VLAN, TCP flags, timestamps.
    """
    try:
        # Layer fields
        src_ip = packet.l3_field.get("src_IP_str", "")
        dst_ip = packet.l3_field.get("dest_IP_str", "")
        src_port = packet.l4_field.get("src_port", 0)
        dst_port = packet.l4_field.get("dest_port", 0)
        vlan = packet.l2_field.get("vlan", None)
        ttl = packet.l3_field.get("ttl", None)
        window = packet.l4_field.get("window", None)
        flags = packet.l4_field.get("flags", None)
        options = packet.l4_field.get("option_field", {})

        timestamp = datetime.utcnow().isoformat()

        # Define request/response pair
        if proto_type == "TCP":
            pair = (src_ip, dst_ip, src_port, dst_port)
        elif proto_type == "UDP":
            pair = (src_ip, dst_ip, src_port, dst_port)
        elif proto_type == "ICMP":
            pair = packet.l4_field.get("ID", 0)
        elif proto_type == "ARP":
            pair = (src_ip, dst_ip)
        else:
            return template_dict  # skip unsupported

        # Handle request (dst_ip is us)
        if dst_ip == host_ip and src_ip:
            key = packet.get_signature(proto_type)
            if key:
                pair_dict[pair] = key
                if key not in template_dict[proto_type]:
                    template_dict[proto_type][key] = None
                    logging.debug(
                        f"🟢 [REQ][{proto_type}] {timestamp} | "
                        f"Key: {key.hex()[:32]} | From {src_ip}:{src_port} → {dst_ip}:{dst_port} | "
                        f"TTL: {ttl} | VLAN: {vlan}"
                    )

        # Handle response (src_ip is us)
        elif src_ip == host_ip and pair in pair_dict:
            if proto_type == "ICMP" and packet.l4_field.get("icmp_type") == 3:
                key = packet.get_signature("UDP")
                if key and key not in template_dict["UDP"]:
                    template_dict["UDP"][key] = None
                    logging.debug(
                        f"🔄 [RESP][ICMP→UDP] {timestamp} | Fallback key: {key.hex()[:32]} | VLAN: {vlan}"
                    )
            else:
                key = pair_dict[pair]
                if key and packet.packet:
                    template_dict[proto_type][key] = packet.packet
                    hex_preview = packet.packet.hex()[:64] + ("..." if len(packet.packet.hex()) > 64 else "")
                    logging.debug(
                        f"📤 [RESP][{proto_type}] {timestamp} | "
                        f"Key: {key.hex()[:32]} | To {dst_ip}:{dst_port} | TTL: {ttl} | VLAN: {vlan} | "
                        f"Window: {window} | TCP Flags: {flags} | "
                        f"Options: {options} | Data: {hex_preview}"
                    )

        return template_dict

    except Exception as e:
        logging.warning(f"⚠️ templateSynthesis error: {e}")
        return template_dict
