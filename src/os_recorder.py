# src/os_recorder.py
import logging
from datetime import datetime
from src.fingerprint_gen import generateKey


def templateSynthesis(packet, proto_type, template_dict, pair_dict, host_ip, export_base=None):
    """
    Synthesizes normalized fingerprint templates for incoming and outgoing packets.

    Args:
        packet: Parsed Packet object
        proto_type: TCP, UDP, ICMP, etc.
        template_dict: Dictionary of normalized key => packet
        pair_dict: (src, dst, sport, dport) => key
        host_ip: IP address for filtering incoming/outgoing
        export_base: optional base folder for exporting per-template .pcap

    Returns:
        template_dict updated with new request/response templates
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

        if proto_type in ("TCP", "UDP"):
            pair = (src_ip, dst_ip, src_port, dst_port)
        elif proto_type == "ICMP":
            pair = packet.l4_field.get("ID", 0)
        elif proto_type == "ARP":
            pair = (src_ip, dst_ip)
        else:
            return template_dict

        # Incoming request to host
        if dst_ip == host_ip:
            key = generateKey(packet, proto_type)
            pair_dict[pair] = key
            if key not in template_dict[proto_type]:
                template_dict[proto_type][key] = None
                logging.debug(
                    f"🟢 [{proto_type}] REQ {timestamp} | Key: {key.hex()[:32]} | "
                    f"From {src_ip}:{src_port} → {dst_ip}:{dst_port} | TTL: {ttl} | VLAN: {vlan}"
                )

        # Outgoing response from host
        elif src_ip == host_ip and pair in pair_dict:
            key = pair_dict[pair]
            if template_dict[proto_type].get(key):
                logging.warning(f"⚠️ Collision: Multiple responses for same key {key.hex()[:16]}")
            template_dict[proto_type][key] = packet.packet

            hex_preview = packet.packet.hex()[:64] + ("..." if len(packet.packet.hex()) > 64 else "")
            logging.debug(
                f"📤 [{proto_type}] RESP {timestamp} | Key: {key.hex()[:32]} | To {dst_ip}:{dst_port} | "
                f"TTL: {ttl} | Window: {window} | Flags: {flags} | Options: {options}"
            )

            # Optional export per-template
            if export_base:
                from scapy.all import wrpcap
                import os
                template_path = os.path.join(export_base, proto_type.lower())
                os.makedirs(template_path, exist_ok=True)
                wrpcap(os.path.join(template_path, f"{key.hex()[:16]}.pcap"), [packet.packet])

        return template_dict

    except Exception as e:
        logging.warning(f"⚠️ templateSynthesis error: {e}")
        return template_dict
