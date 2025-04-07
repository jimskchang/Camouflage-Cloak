# src/os_recorder.py

import logging
import os
from datetime import datetime
from scapy.all import wrpcap, Ether
from src.fingerprint_gen import generateKey
from src.settings import OS_RECORD_PATH


def templateSynthesis(packet, proto_type, template_dict, pair_dict, host_ip):
    """
    Enhanced template synthesis with:
    ✅ Normalized + hashed keys (SHA256)
    ✅ Per-template PCAP saving
    ✅ Collision detection
    ✅ Future extension: DNS/HTTP awareness
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

        # Future hook: application layer detection
        app_proto = "dns" if dst_port == 53 or src_port == 53 else "http" if dst_port in [80, 8080, 443] else None

        # Correlation pair
        if proto_type in ("TCP", "UDP"):
            pair = (src_ip, dst_ip, src_port, dst_port)
        elif proto_type == "ICMP":
            pair = packet.l4_field.get("ID", 0)
        elif proto_type == "ARP":
            pair = (src_ip, dst_ip)
        else:
            return template_dict

        # Probe
        if dst_ip == host_ip:
            key = generateKey(packet, proto_type)
            if not key:
                return template_dict

            if key in template_dict[proto_type] and template_dict[proto_type][key] is not None:
                logging.warning(f"⚠️ Collision: key already recorded for {proto_type.upper()} | {key.hex()[:16]}")

            pair_dict[pair] = key
            if key not in template_dict[proto_type]:
                template_dict[proto_type][key] = None

                logging.debug(
                    f"🟢 [REQ][{proto_type}] {timestamp} | Key: {key.hex()[:32]} | "
                    f"{src_ip}:{src_port} ➔ {dst_ip}:{dst_port} | VLAN: {vlan} | TTL: {ttl}"
                )

        # Response
        elif src_ip == host_ip and pair in pair_dict:
            key = pair_dict[pair]
            existing = template_dict[proto_type].get(key)
            if existing and existing != packet.packet:
                logging.warning(f"⚠️ Collision: hash matched but payloads differ for {proto_type.upper()} key")

            template_dict[proto_type][key] = packet.packet

            hex_preview = packet.packet.hex()[:64] + ("..." if len(packet.packet.hex()) > 64 else "")
            logging.debug(
                f"📤 [RESP][{proto_type}] {timestamp} | Key: {key.hex()[:32]} | "
                f"To {dst_ip}:{dst_port} | TCP Flags: {flags} | Window: {window} | VLAN: {vlan} | Data: {hex_preview}"
            )

            # Save individual .pcap
            out_dir = os.path.join(OS_RECORD_PATH, "pcap", proto_type.lower())
            os.makedirs(out_dir, exist_ok=True)
            out_path = os.path.join(out_dir, f"{key.hex()[:32]}.pcap")
            try:
                wrpcap(out_path, [Ether(packet.packet)])
            except Exception as e:
                logging.warning(f"⚠️ Failed to save per-template PCAP: {e}")

        return template_dict

    except Exception as e:
        logging.warning(f"⚠️ templateSynthesis error: {e}")
        return template_dict
