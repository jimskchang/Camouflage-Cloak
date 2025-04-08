# src/os_recorder.py

import logging
import os
from datetime import datetime
from src.fingerprint_gen import generateKey
from scapy.all import wrpcap

def templateSynthesis(packet, proto_type, template_dict, pair_dict, host_ip, base_path=None, enable_l7=False):
    """
    Synthesizes packet templates from incoming traffic based on normalized key and response matching.

    Args:
        packet: A parsed Packet instance.
        proto_type: "TCP", "UDP", "ICMP", or "ARP".
        template_dict: Template storage by protocol and normalized key.
        pair_dict: Lookup dictionary to match request-response.
        host_ip: IP address of the host being recorded.
        base_path: Optional directory to export individual PCAPs.
        enable_l7: Whether to enable DNS/HTTP markers or future parsing.

    Returns:
        Updated template_dict.
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

        # Request identification
        if proto_type in ("TCP", "UDP"):
            pair = (src_ip, dst_ip, src_port, dst_port)
        elif proto_type == "ICMP":
            pair = packet.l4_field.get("ID", 0)
        elif proto_type == "ARP":
            pair = (src_ip, dst_ip)
        else:
            return template_dict

        # --- Incoming Request ---
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

        # --- Outgoing Response ---
        elif src_ip == host_ip and pair in pair_dict:
            key = pair_dict[pair]

            if key in template_dict[proto_type] and template_dict[proto_type][key] is not None:
                logging.warning(f"⚠️ Collision: duplicate response for key {key.hex()[:32]}")
            else:
                template_dict[proto_type][key] = packet.packet

            preview = packet.packet.hex()[:64] + ("..." if len(packet.packet.hex()) > 64 else "")
            logging.debug(
                f"📤 [RESP][{proto_type}] {timestamp} | "
                f"Key: {key.hex()[:32]} | To {dst_ip}:{dst_port} | TTL={ttl} | Window={window} | "
                f"Flags={flags} | Options={options} | Data: {preview}"
            )

            # Optionally save per-template PCAP
            if base_path:
                pcap_name = f"{proto_type.lower()}_{key.hex()[:16]}.pcap"
                pcap_path = os.path.join(base_path, pcap_name)
                try:
                    wrpcap(pcap_path, [packet.packet])
                    logging.debug(f"💾 Saved template PCAP: {pcap_path}")
                except Exception as e:
                    logging.warning(f"⚠️ Failed to write PCAP: {e}")

        return template_dict

    except Exception as e:
        logging.warning(f"⚠️ templateSynthesis error: {e}")
        return template_dict
