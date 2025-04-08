# src/os_recorder.py

import logging
import os
from datetime import datetime
from scapy.all import wrpcap
from src.fingerprint_gen import generateKey


def templateSynthesis(packet, proto_type, template_dict, pair_dict, host_ip, base_path=None, enable_l7=False):
    """
    Synthesizes normalized templates for OS deception based on packet fingerprint.

    Args:
        packet: A parsed Packet instance.
        proto_type: Protocol string: "TCP", "UDP", "ICMP", or "ARP".
        template_dict: Dictionary holding synthesized templates.
        pair_dict: Dictionary mapping packet pairs to keys.
        host_ip: IP of the target being fingerprinted.
        base_path: Optional directory to write individual pcap files.
        enable_l7: Enable detection hooks for DNS/HTTP/etc. (future use).

    Returns:
        Updated template_dict
    """
    try:
        src_ip = packet.l3_field.get("src_IP_str")
        dst_ip = packet.l3_field.get("dest_IP_str")
        src_port = packet.l4_field.get("src_port")
        dst_port = packet.l4_field.get("dest_port")
        ttl = packet.l3_field.get("ttl")
        vlan = packet.l2_field.get("vlan")
        flags = packet.l4_field.get("flags") if proto_type == "TCP" else None
        options = packet.l4_field.get("option_field") if proto_type == "TCP" else {}
        window = packet.l4_field.get("window") if proto_type == "TCP" else None
        timestamp = datetime.utcnow().isoformat()

        # Pair definition by protocol
        if proto_type in ("TCP", "UDP"):
            pair = (src_ip, dst_ip, src_port, dst_port)
        elif proto_type == "ICMP":
            pair = packet.l4_field.get("ID", 0)
        elif proto_type == "ARP":
            pair = (src_ip, dst_ip)
        else:
            return template_dict

        # --- Incoming request ---
        if dst_ip == host_ip:
            key = generateKey(packet, proto_type)
            pair_dict[pair] = key
            if key not in template_dict[proto_type]:
                template_dict[proto_type][key] = None
                logging.debug(
                    f"🟢 [REQ][{proto_type}] {timestamp} | "
                    f"{src_ip}:{src_port} → {dst_ip}:{dst_port} | Key={key.hex()[:32]} | TTL={ttl} | VLAN={vlan}"
                )

        # --- Outgoing response ---
        elif src_ip == host_ip and pair in pair_dict:
            key = pair_dict[pair]
            if key in template_dict[proto_type] and template_dict[proto_type][key]:
                logging.warning(f"⚠️ Duplicate response for key: {key.hex()[:32]}")
            else:
                template_dict[proto_type][key] = packet.packet
                logging.debug(
                    f"📤 [RESP][{proto_type}] {timestamp} | "
                    f"To {dst_ip}:{dst_port} | Key={key.hex()[:32]} | TTL={ttl} | Window={window} | "
                    f"Flags={flags} | Options={options} | VLAN={vlan}"
                )

                # Write PCAP if requested
                if base_path:
                    pcap_name = f"{proto_type.lower()}_{key.hex()[:16]}.pcap"
                    pcap_path = os.path.join(base_path, pcap_name)
                    try:
                        wrpcap(pcap_path, [packet.packet])
                        logging.debug(f"💾 Saved per-template PCAP: {pcap_path}")
                    except Exception as e:
                        logging.warning(f"⚠️ Failed to write PCAP: {e}")

        return template_dict

    except Exception as e:
        logging.warning(f"⚠️ templateSynthesis exception: {e}")
        return template_dict
