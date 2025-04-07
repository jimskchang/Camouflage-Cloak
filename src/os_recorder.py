# src/os_recorder.py

import logging
import os
from datetime import datetime
from src.fingerprint_gen import generateKey
from scapy.utils import wrpcap

def templateSynthesis(packet, proto_type, template_dict, pair_dict, host_ip, base_path=None):
    """
    Synthesizes a fingerprint template from observed packets.
    Supports per-template export (.pcap), VLAN detection, and future L7 extensions.
    """
    try:
        src_ip = packet.l3_field.get("src_IP_str")
        dst_ip = packet.l3_field.get("dest_IP_str")
        src_port = packet.l4_field.get("src_port")
        dst_port = packet.l4_field.get("dest_port")
        vlan = packet.l2_field.get("vlan")
        ttl = packet.l3_field.get("ttl")
        flags = packet.l4_field.get("flags") if proto_type == "TCP" else None
        options = packet.l4_field.get("option_field") if proto_type == "TCP" else {}
        ja3 = packet.l7_field.get("ja3") if hasattr(packet, "l7_field") else None
        timestamp = datetime.utcnow().isoformat()

        if proto_type in ("TCP", "UDP"):
            pair = (src_ip, dst_ip, src_port, dst_port)
        elif proto_type == "ICMP":
            pair = packet.l4_field.get("ID", 0)
        elif proto_type == "ARP":
            pair = (src_ip, dst_ip)
        else:
            return template_dict

        # Incoming request → generate key
        if dst_ip == host_ip:
            key = generateKey(packet, proto_type, use_hash=True)
            pair_dict[pair] = key
            if key not in template_dict[proto_type]:
                template_dict[proto_type][key] = None
                logging.debug(
                    f"🟢 [REQ][{proto_type}] {timestamp} | Key: {key.hex()[:32]} | "
                    f"From {src_ip}:{src_port} → {dst_ip}:{dst_port} | TTL={ttl} | VLAN={vlan}"
                )
            else:
                logging.warning(f"⚠️ [COLLISION] Key already exists for {proto_type}: {key.hex()[:16]}")

        # Outgoing response → store template
        elif src_ip == host_ip and pair in pair_dict:
            key = pair_dict[pair]
            template_dict[proto_type][key] = packet.packet
            hex_preview = packet.packet.hex()[:64] + ("..." if len(packet.packet.hex()) > 64 else "")
            logging.debug(
                f"📤 [RESP][{proto_type}] {timestamp} | Key: {key.hex()[:32]} | "
                f"To {dst_ip}:{dst_port} | TTL={ttl} | Flags={flags} | Options={options} | VLAN={vlan} | "
                f"Data: {hex_preview}"
            )

            # Optionally export to .pcap for replay
            if base_path:
                proto_dir = os.path.join(base_path, proto_type.lower())
                os.makedirs(proto_dir, exist_ok=True)
                fname = f"{proto_type}_{key.hex()[:16]}.pcap"
                fpath = os.path.join(proto_dir, fname)
                try:
                    wrpcap(fpath, packet.packet)
                    logging.debug(f"📦 Saved response to {fpath}")
                except Exception as e:
                    logging.warning(f"⚠️ Failed to write pcap for key={key.hex()[:16]}: {e}")

        return template_dict

    except Exception as e:
        logging.warning(f"⚠️ templateSynthesis error: {e}")
        return template_dict
