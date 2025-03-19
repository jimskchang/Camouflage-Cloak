import logging
import os
import json
import socket
import struct
from datetime import datetime, timedelta
from typing import List, Dict, Any

import src.settings as settings
from src.Packet import Packet
from src.tcp import TcpConnect
from scapy.all import IP, TCP, UDP, ICMP, Ether, sendp

class OsDeceiver:
    def __init__(self, target_host: str, target_os: str):
        """
        Initializes OS deception with target details and ensures correct paths.
        """
        self.host = target_host
        self.os = target_os
        self.conn = TcpConnect(target_host)
        self.port_seq: List[int] = [4441, 5551, 6661]

        # ✅ Set correct path to `os_record` directory
        self.os_record_path = f"/home/user/Camouflage-Cloak/os_record/{self.os}"

        logging.info(f"📌 OS Deception Initialized for {self.os}. OS Record Path: {self.os_record_path}")

        # ✅ Ensure OS record directory exists
        if not os.path.exists(self.os_record_path):
            logging.error(f"❌ OS fingerprint directory {self.os_record_path} does not exist!")
            return

    def load_file(self, pkt_type: str) -> Dict[str, Any]:
        """
        Load OS deception template records dynamically from the selected OS directory.
        """
        file_path = os.path.join(self.os_record_path, f"{pkt_type}_record.txt")

        try:
            if not os.path.exists(file_path):
                logging.error(f"❌ Error: {file_path} not found.")
                return {}

            if not os.access(file_path, os.R_OK):
                logging.error(f"❌ Permission error: Cannot read {file_path}.")
                return {}

            with open(file_path, 'r', encoding='utf-8') as file:
                packet_data = file.read().strip()
                if not packet_data:
                    logging.warning(f"⚠ Warning: {file_path} is empty.")
                    return {}

                packet_dict = json.loads(packet_data)
                return {k: v for k, v in packet_dict.items() if v is not None}

        except (json.JSONDecodeError, FileNotFoundError, IOError, PermissionError) as e:
            logging.error(f"❌ Error loading {file_path}: {e}")
            return {}

    def os_deceive(self, timeout_minutes: int) -> None:
        """
        Perform OS deception based on template packets.
        Stops after the specified timeout.
        """
        logging.info(f'📌 Loading OS deception template for {self.os} from {self.os_record_path}')
        template_dict = {p: self.load_file(p) for p in ['arp', 'tcp', 'udp', 'icmp']}

        timeout = datetime.now() + timedelta(minutes=timeout_minutes)
        
        while datetime.now() < timeout:
            try:
                raw_pkt, _ = self.conn.sock.recvfrom(65565)
                pkt = Packet(packet=raw_pkt)
                pkt.unpack()

                if (pkt.l3 == 'ip' and pkt.l3_field.get('dest_IP') == socket.inet_aton(self.host)) or \
                   (pkt.l3 == 'arp' and pkt.l3_field.get('recv_ip') == socket.inet_aton(self.host)):
                    rsp = deceived_pkt_synthesis(pkt, template_dict, self.os)
                    if rsp:
                        logging.info(f'📌 Sending deceptive {pkt.l3} packet for {self.os}.')
                        sendp(rsp, iface=settings.INTERFACE, verbose=False)
            except Exception as e:
                logging.error(f"❌ Error in OS deception process: {e}")
                continue

        logging.info(f"🛑 OS Deception for {self.os} completed.")

def deceived_pkt_synthesis(req: Packet, template: Dict[str, Any], os_type: str) -> bytes:
    """
    Generate a deceptive packet based on the request and template for the specified OS.
    """
    try:
        raw_template = template.get(req.l3, {}).get(req.packet)
        if not raw_template:
            return b''  # No deception data available
        
        template_pkt = Packet(raw_template)
        template_pkt.unpack()

        if req.l3 == 'tcp':
            return craft_tcp_response(req, os_type)

        elif req.l3 == 'icmp':
            return craft_icmp_response(req, os_type)

        elif req.l3 == 'udp':
            return craft_udp_response(req, os_type)

        elif req.l3 == 'arp':
            return craft_arp_response(req)

        return b''  # Unsupported packet type
    except Exception as e:
        logging.error(f"❌ Error synthesizing deceptive packet: {e}")
        return b''

def craft_tcp_response(req: Packet, os_type: str) -> bytes:
    """
    Craft a deceptive TCP response based on the selected OS.
    """

    # ✅ Updated OS Mapping with Correct `winserverYYYY` Names
    ttl_map = {
        "win10": 128,
        "win11": 128,
        "winserver2016": 128,
        "winserver2022": 128,
        "winserver2025": 255,  
        "linux": 64,
        "macos": 64
    }

    window_map = {
        "win10": 64240,
        "win11": 65535,
        "winserver2016": 65535,
        "winserver2022": 64240,
        "winserver2025": 65535,  
        "linux": 5840,
        "macos": 65535
    }

    ttl = ttl_map.get(os_type.lower(), 64)
    window_size = window_map.get(os_type.lower(), 5840)

    try:
        pkt = Ether() / IP(src=req.l3_field['dest_IP'], dst=req.l3_field['src_IP'], ttl=ttl) / \
              TCP(sport=req.l4_field['dest_port'], dport=req.l4_field['src_port'], flags="SA",
                  window=window_size, options=[("MSS", 1460), ("NOP", None), ("WScale", 8)])
        return pkt.build()
    except Exception as e:
        logging.error(f"❌ Error crafting TCP response: {e}")
        return b''

def craft_icmp_response(req: Packet, os_type: str) -> bytes:
    """
    Craft a deceptive ICMP response based on the selected OS.
    """

    ttl_map = {
        "win10": 128,
        "win11": 128,
        "winserver2016": 128,
        "winserver2022": 128,
        "winserver2025": 255,
        "linux": 64,
        "macos": 64
    }

    ttl = ttl_map.get(os_type.lower(), 64)

    try:
        pkt = Ether() / IP(src=req.l3_field['dest_IP'], dst=req.l3_field['src_IP'], ttl=ttl) / \
              ICMP(type=0, code=0, id=req.l4_field['ID'], seq=req.l4_field['seq'])
        return pkt.build()
    except Exception as e:
        logging.error(f"❌ Error crafting ICMP response: {e}")
        return b''
