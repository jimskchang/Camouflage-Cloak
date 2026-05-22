import os
import json
import time
import socket
import random
import logging
from datetime import datetime, timedelta
from collections import defaultdict
from scapy.all import IP, TCP, UDP, ICMP, Ether, wrpcap, get_if_addr, sendp

from src.settings import get_os_fingerprint, get_mac_address
from src.Packet import Packet
from src.tcp import TcpConnect
from src.response import synthesize_response
from src.fingerprint_utils import gen_key
from src.ja3_extractor import extract_ja3, match_ja3_rule
from src import l7_tracker

class OsDeceiver:
    def __init__(self, target_host, target_os, dest=None, nic=None, replay=False, interactive=False, enable_dns=False, enable_ja3=False):
        self.nic = nic
        self.mac = get_mac_address(nic)
        self.host = get_if_addr(nic)
        self.dest = dest or os.path.join("os_record", target_os)
        os.makedirs(self.dest, exist_ok=True)

        self.conn = TcpConnect(self.host, nic=self.nic)
        self.os = target_os.lower()
        self.replay = replay
        self.enable_ja3 = enable_ja3
        
        # --- OS Template Configuration ---
        os_template = get_os_fingerprint(self.os)
        self.ttl = os_template.get("ttl", 64)
        self.window = os_template.get("window", 8192)
        self.tcp_options_data = os_template.get("tcp_options", {}) 
        
        # IPID Profile Configuration
        self.ipid_mode = os_template.get("ipid", "increment")
        self.current_ipid = random.randint(1000, 60000)

        self.os_flags = {
            "df": os_template.get("df", False),
            "tos": os_template.get("tos", 0),
            "ecn": os_template.get("ecn", 0),
        }

        self.sent_packets = []
        self.protocol_stats = defaultdict(int)
        self.start_time = time.time()

    def load_file(self, ptype):
        """Mock/Placeholder or dynamic recovery of template dictionaries"""
        # If your templates are saved as JSON configuration files:
        filepath = os.path.join("templates", f"{self.os}_{ptype}.json")
        if os.path.exists(filepath):
            with open(filepath, 'r') as f:
                return json.load(f)
        return {}

    def _get_ipid(self):
        """Calculates IPID according to targeted OS profile rules"""
        if self.ipid_mode == "random":
            return random.randint(1, 65535)
        elif self.ipid_mode == "zero":
            return 0
        else: # increment
            self.current_ipid = (self.current_ipid + 1) % 65535
            return self.current_ipid

    def _get_timestamp_val(self):
        """Calculates simulated uptime values"""
        return int((time.time() - self.start_time) * 100) 

    def get_tcp_options(self, ts_echo=0):
        """Generates realistic TCP Options profiles"""
        options = []
        options.append(('MSS', self.tcp_options_data.get("mss", 1460)))
        
        if self.tcp_options_data.get("sack", True):
            options.append(('SAckOK', b''))
            
        if "wscale" in self.tcp_options_data:
            options.append(('WScale', self.tcp_options_data["wscale"]))
            
        if self.tcp_options_data.get("timestamp", True):
            options.append(('Timestamp', (self._get_timestamp_val(), ts_echo)))
            
        return options

    def _send_packet(self, packet):
        """Lower engine packet injection layer"""
        try:
            sendp(packet, iface=self.nic, verbose=False)
            self.sent_packets.append(bytes(packet))
        except Exception as e:
            logging.error(f"❌ Failed to send packet: {e}")

    def os_deceive(self, timeout_minutes=5):
        logging.info(f"🚦 Starting OS deception for: {self.os.upper()} on {self.nic}")
        
        templates = {ptype: self.load_file(ptype) for ptype in ["tcp", "icmp", "udp", "arp"]}
        timeout = datetime.now() + timedelta(minutes=timeout_minutes)

        while datetime.now() < timeout:
            try:
                raw, addr = self.conn.sock.recvfrom(65535)
                pkt = Packet(raw)
                pkt.interface = self.nic
                pkt.unpack()

                proto = pkt.l4 if pkt.l4 else pkt.l3
                if not proto:
                    continue
                
                # --- Template Match Engine ---
                key, _ = gen_key(proto, pkt.packet)
                template = templates.get(proto, {}).get(key)
                
                if template:
                    response = synthesize_response(pkt, template, ttl=self.ttl, window=self.window, deceiver=self)
                    if response:
                        # Ensure we don't accidentally stack nested Ethernet frames
                        out_pkt = response if isinstance(response, Ether) else Ether(response)
                        self._send_packet(out_pkt)
                        self.protocol_stats[proto.upper()] += 1
                else:
                    # Defensive Port/OS Spoof Behavior for non-profiled traffic
                    if proto == "udp":
                        self.send_icmp_port_unreachable(pkt)
                    elif proto == "tcp":
                        self.send_tcp_rst(pkt)

            except Exception as e:
                logging.debug(f"⚠️ Packet processing error: {e}")

        self.export_data()

    def send_tcp_rst(self, pkt):
        """Constructs and injects a tailored TCP RST signature packet"""
        ip_flags = "DF" if self.os_flags["df"] else None
        
        # Grab target destination MAC safely if accessible via custom Packet class properties
        dst_mac = pkt.packet_field.get("src_mac", "ff:ff:ff:ff:ff:ff") 

        ip = IP(
            src=pkt.l3_field["dest_IP_str"], 
            dst=pkt.l3_field["src_IP_str"], 
            ttl=self.ttl,
            tos=self.os_flags["tos"],
            flags=ip_flags,
            id=self._get_ipid()
        )
        
        tcp = TCP(
            sport=pkt.l4_field["dest_port"], 
            dport=pkt.l4_field["src_port"], 
            flags="R", 
            window=self.window,
            options=self.get_tcp_options()
        )
        
        rst = Ether(src=self.mac, dst=dst_mac) / ip / tcp
        self._send_packet(rst)
        self.protocol_stats["TCP"] += 1

    def send_icmp_port_unreachable(self, pkt):
        """Constructs an accurate ICMP Destination Unreachable response"""
        dst_mac = pkt.packet_field.get("src_mac", "ff:ff:ff:ff:ff:ff")

        ip = IP(
            src=pkt.l3_field["dest_IP_str"], 
            dst=pkt.l3_field["src_IP_str"], 
            ttl=self.ttl,
            tos=self.os_flags["tos"],
            id=self._get_ipid()
        )
        icmp = ICMP(type=3, code=3)
        
        # Dynamically isolate inner IP layer headers from the original byte array safely
        # Slicing the raw packet from the start of the network layer string
        inner_ip_bytes = pkt.packet[14:] 
        
        reply = Ether(src=self.mac, dst=dst_mac) / ip / icmp / bytes(inner_ip_bytes)[:28]
        
        self._send_packet(reply)
        self.protocol_stats["ICMP"] += 1

    def export_data(self):
        """Saves generated session metrics safely"""
        logging.info("💾 Exporting deception metrics logs...")
        # Write your output data collection functions here
