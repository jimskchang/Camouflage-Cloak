# src/os_recorder.py

import logging
from datetime import datetime
from src.fingerprint_gen import generateKey  # ✅ Import generateKey from isolated module

def templateSynthesis(packet, proto_type, template_dict, pair_dict, host_ip):
    """
    Template synthesis logic for OS fingerprinting.
    Associates request/response packets with normalized keys.
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

        # Define session pair
        if proto_type in ("TCP", "UDP"):
            pair = (src_ip, dst_ip, src_port, dst_port)
        elif proto_type == "ICMP":
            pair = packet.l4_field.get("ID", 0)
        elif proto_type == "ARP":
            pair = (src_ip, dst_ip)
        else:
            return template_dict

        # Incoming probe (e.g. SYN, echo-request)
        if dst_ip == host_ip:
            key = generateKey(packet, proto_type)
            pair_dict[pair] = key
            if key not in template_dict[proto_type]:
                template_dict[proto_type][key] = None
                logging.debug(
                    f"🟢 [REQ][{proto_type}] {timestamp} | "
                    f"Key: {key.hex()[:32]} | From {src_ip}:{src_port} → {dst_ip}:{dst_port} | "
                    f"TTL: {ttl} | VLAN: {vlan}"
                )

        # Outgoing reply
        elif src_ip == host_ip and pair in pair_dict:
            if proto_type == "ICMP" and packet.l4_field.get("icmp_type") == 3:
                # ICMP Unreachable maps to previous UDP probe
                key = generateKey(packet, "UDP")
                if key not in template_dict["UDP"]:
                    template_dict["UDP"][key] = None
                    logging.debug(
                        f"🔄 [RESP][ICMP→UDP] {timestamp} | Fallback key: {key.hex()[:32]} | VLAN: {vlan}"
                    )
            else:
                key = pair_dict[pair]
                template_dict[proto_type][key] = packet.packet
                preview = packet.packet.hex()[:64] + ("..." if len(packet.packet.hex()) > 64 else "")
                logging.debug(
                    f"📤 [RESP][{proto_type}] {timestamp} | Key: {key.hex()[:32]} | "
                    f"To {dst_ip}:{dst_port} | TTL: {ttl} | VLAN: {vlan} | "
                    f"Window: {window} | TCP Flags: {flags} | Options: {options} | Data: {preview}"
                )

        return template_dict

    except Exception as e:
        logging.warning(f"⚠️ templateSynthesis error: {e}")
        return template_dict
