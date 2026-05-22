import os
import json
import logging
from datetime import datetime
from scapy.all import wrpcap

from src.fingerprint_gen import generateKey
from src.ja3_extractor import extract_ja3_from_packet
from src.l7_tracker import log_http_banner

# JA3 per-IP log memory cache
ja3_log = {}

def templateSynthesis(packet, proto_type, template_dict, pair_dict, host_ip, base_path=None, enable_l7=False):
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

        if proto_type not in template_dict:
            template_dict[proto_type] = {}

        # --- JA3 extraction ---
        ja3_hash = None
        if proto_type == "TCP" and dst_port == 443:
            ja3_hash = extract_ja3_from_packet(packet)
            if ja3_hash:
                ja3_log.setdefault(src_ip, []).append(ja3_hash)
                logging.info(f"🔍 JA3 from {src_ip}: {ja3_hash}")

        # --- L7 banner logging ---
        if enable_l7 and proto_type == "TCP":
            banner_type = packet.l4_field.get("http_banner_type")
            user_agent = packet.l4_field.get("user_agent")
            if banner_type:
                log_http_banner(src_ip, ja3_hash, banner_type, user_agent)

        # --- FIXED: Symmetrical Request-Response Pair Identification ---
        if proto_type in ("TCP", "UDP"):
            # Sort IPs and ports to guarantee identical mapping keys regardless of direction
            ips = sorted([src_ip, dst_ip])
            ports = sorted([src_port, dst_port])
            pair = (ips[0], ips[1], ports[0], ports[1])
        elif proto_type == "ICMP":
            pair = packet.l4_field.get("ID", 0)
        elif proto_type == "ARP":
            ips = sorted([src_ip, dst_ip])
            pair = (ips[0], ips[1])
        else:
            return template_dict

        # --- Incoming Request ---
        if dst_ip == host_ip:
            key = generateKey(packet, proto_type)
            pair_dict[pair] = key
            if key not in template_dict[proto_type]:
                template_dict[proto_type][key] = None
                logging.debug(
                    f"🟢 [REQ][{proto_type}] {timestamp} | Key={key.hex()[:32]} | {src_ip}:{src_port} → {dst_ip}:{dst_port} | TTL={ttl} VLAN={vlan}"
                )

        # --- Outgoing Response ---
        elif src_ip == host_ip and pair in pair_dict:
            key = pair_dict[pair]
            
            if key in template_dict[proto_type] and template_dict[proto_type][key] is not None:
                logging.warning(f"⚠️ Duplicate response for key {key.hex()[:32]}")
            else:
                template_dict[proto_type][key] = packet.packet

            preview = packet.packet.hex()[:64] + ("..." if len(packet.packet.hex()) > 64 else "")
            logging.debug(
                f"📤 [RESP][{proto_type}] {timestamp} | Key={key.hex()[:32]} | {src_ip}:{src_port} → {dst_ip}:{dst_port} | TTL={ttl} | Flags={flags} | Opts={options} | Data={preview}"
            )

            # Save per-template PCAP
            if base_path:
                pcap_name = f"{proto_type.lower()}_{key.hex()[:16]}.pcap"
                pcap_path = os.path.join(base_path, pcap_name)
                try:
                    wrpcap(pcap_path, [packet.packet])
                    logging.debug(f"💾 Saved PCAP: {pcap_path}")
                except Exception as e:
                    logging.warning(f"⚠️ Failed to write PCAP: {e}")
            
            # Clean memory out of pair_dict after response resolution to prevent leaks
            del pair_dict[pair]

        return template_dict

    except Exception as e:
        logging.warning(f"⚠️ templateSynthesis error: {e}")
        return template_dict

def export_ja3_log(path, nic):
    global ja3_log
    try:
        if not ja3_log:
            return
        outfile = os.path.join(path, f"ja3_observed_{nic}.json")
        with open(outfile, "w") as f:
            json.dump(ja3_log, f, indent=2)
        logging.info(f"🔐 JA3 log exported → {outfile}")
        ja3_log.clear() # Clear memory allocation cache safely
    except Exception as e:
        logging.warning(f"⚠️ Failed to export JA3 log: {e}")
