# src/os_recorder.py
import logging
from datetime import datetime
from src.fingerprint_gen import generateKey

def templateSynthesis(packet, proto_type, template_dict, pair_dict, host_ip):
    """
    Enhanced template synthesis with debug logging:
    normalizes and hashes key using fingerprint_gen.generateKey().
    Supports L7 markers like DNS/HTTP, VLAN tagging, etc.
    """
    try:
        src_ip = packet.l3_field.get("src_IP_str")
        dst_ip = packet.l3_field.get("dest_IP_str")
        src_port = packet.l4_field.get("src_port")
        dst_port = packet.l4_field.get("dest_port")

        timestamp = datetime.utcnow().isoformat()
        vlan = packet.l2_field.get("vlan")
        flags = packet.l4_field.get("flags") if proto_type == "TCP" else None
        ttl = packet.l3_field.get("ttl")
        window = packet.l4_field.get("window") if proto_type == "TCP" else None
        options = packet.l4_field.get("option_field") if proto_type == "TCP" else {}

        # Define packet pair for request/response correlation
        if proto_type in ("TCP", "UDP"):
            pair = (src_ip, dst_ip, src_port, dst_port)
        elif proto_type == "ICMP":
            pair = packet.l4_field.get("ID", 0)
        elif proto_type == "ARP":
            pair = (src_ip, dst_ip)
        else:
            return template_dict

        # Incoming Request
        if dst_ip == host_ip:
            key = generateKey(packet, proto_type, use_hash=True)
            pair_dict[pair] = key
            if key not in template_dict[proto_type]:
                template_dict[proto_type][key] = None
                logging.debug(
                    f"🟢 [REQ][{proto_type}] {timestamp} | "
                    f"Key: {key.hex()[:32]} | From {src_ip}:{src_port} → {dst_ip}:{dst_port} | "
                    f"TTL: {ttl} | VLAN: {vlan}"
                )

        # Outgoing Response
        elif src_ip == host_ip and pair in pair_dict:
            key = pair_dict[pair]
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
