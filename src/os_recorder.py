"""OS Fingerprint Template Synthesis - Refactored for unified SharedState.

This module synthesizes request-response packet pairs into learnable fingerprint templates.
All shared state (JA3 log, L7 tracking, templates) is accessed via SharedState with proper locking.
"""

import os
import json
import logging
from datetime import datetime
from scapy.all import wrpcap

from src.fingerprint_gen import generateKey
from src.ja3_extractor import extract_ja3_from_packet


def templateSynthesis(packet, proto_type, shared_state, host_ip, base_path=None, enable_l7=False):
    """
    Template synthesis with multiprocessing-safe state management.
    
    Synthesizes request-response pairs using unified SharedState container.
    All writes to shared state are protected by appropriate locks.
    
    Args:
        packet: Packet object to process
        proto_type: Protocol type ("TCP", "UDP", "ICMP", "ARP")
        shared_state: SharedState instance (unified container for cross-process state)
        host_ip: Host IP address (for identifying requests vs. responses)
        base_path: Optional base path for PCAP output
        enable_l7: Whether to enable L7 banner logging
    
    Returns:
        dict: Updated template_dict (for backward compatibility)
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

        # === Use shared_state.template_lock to protect template_dict access ===
        with shared_state.template_lock:
            if proto_type not in shared_state.template_dict:
                shared_state.template_dict[proto_type] = {}
            template_dict = shared_state.template_dict  # Local reference

        # --- JA3 extraction with multiprocess-safe storage ---
        ja3_hash = None
        if proto_type == "TCP" and dst_port == 443:
            ja3_hash = extract_ja3_from_packet(packet)
            if ja3_hash:
                # === CRITICAL: Use shared_state.ja3_lock to protect concurrent access ===
                with shared_state.ja3_lock:
                    if src_ip not in shared_state.ja3_log:
                        shared_state.ja3_log[src_ip] = []
                    if ja3_hash not in shared_state.ja3_log[src_ip]:
                        shared_state.ja3_log[src_ip].append(ja3_hash)
                logging.info(f"🔍 JA3 from {src_ip}: {ja3_hash}")

        # --- L7 banner logging ---
        if enable_l7 and proto_type == "TCP":
            from src.l7_tracker_refactored import L7Tracker
            banner_type = packet.l4_field.get("http_banner_type")
            user_agent = packet.l4_field.get("user_agent")
            if banner_type:
                tracker = L7Tracker(shared_state)
                tracker.log_http_banner(src_ip, ja3_hash, banner_type, user_agent)

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
            return dict(template_dict) if template_dict else {}

        # --- Incoming Request ---
        if dst_ip == host_ip:
            key = generateKey(packet, proto_type)
            with shared_state.template_lock:
                shared_state.pair_dict[pair] = key
                if key not in shared_state.template_dict[proto_type]:
                    shared_state.template_dict[proto_type][key] = None
                    logging.debug(
                        f"🟢 [REQ][{proto_type}] {timestamp} | Key={key.hex()[:32]} | "
                        f"{src_ip}:{src_port} → {dst_ip}:{dst_port} | TTL={ttl} VLAN={vlan}"
                    )

        # --- Outgoing Response ---
        elif src_ip == host_ip:
            with shared_state.template_lock:
                if pair not in shared_state.pair_dict:
                    return dict(shared_state.template_dict) if shared_state.template_dict else {}
                
                key = shared_state.pair_dict[pair]
                
                if key in shared_state.template_dict[proto_type] and shared_state.template_dict[proto_type][key] is not None:
                    logging.warning(f"⚠️ Duplicate response for key {key.hex()[:32]}")
                else:
                    shared_state.template_dict[proto_type][key] = packet.packet

                preview = packet.packet.hex()[:64] + ("..." if len(packet.packet.hex()) > 64 else "")
                logging.debug(
                    f"📤 [RESP][{proto_type}] {timestamp} | Key={key.hex()[:32]} | "
                    f"{src_ip}:{src_port} → {dst_ip}:{dst_port} | TTL={ttl} | Flags={flags} | "
                    f"Opts={options} | Data={preview}"
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
                del shared_state.pair_dict[pair]

        return dict(shared_state.template_dict) if shared_state.template_dict else {}

    except Exception as e:
        logging.warning(f"⚠️ templateSynthesis error: {e}")
        return {}
