import os
import json
import time
import socket
import random
import logging
from datetime import datetime, timedelta
from collections import defaultdict
from scapy.all import IP, TCP, UDP, ICMP, Ether, wrpcap, get_if_addr

from src.settings import get_os_fingerprint, get_mac_address, CUSTOM_RULES
from src.Packet import Packet
from src.tcp import TcpConnect
from src.response import synthesize_response, export_ja3_observed
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
        
        # --- 核心優化：加載 OS 指紋配置 ---
        os_template = get_os_fingerprint(self.os)
        self.ttl = os_template.get("ttl", 64)
        self.window = os_template.get("window", 8192)
        # 用於記錄特定的 TCP 選項數據
        self.tcp_options_data = os_template.get("tcp_options", {}) 
        
        self.os_flags = {
            "df": os_template.get("df", False),
            "tos": os_template.get("tos", 0),
            "ecn": os_template.get("ecn", 0),
        }

        self.sent_packets = []
        self.protocol_stats = defaultdict(int)

    def get_tcp_options(self, ts_echo=0):
        """
        
        根據 OS 特徵產生精確的 TCP SYN/ACK 選項。
        """
        options = []
        # MSS
        options.append(('MSS', self.tcp_options_data.get("mss", 1460)))
        
        # SackOK
        if self.tcp_options_data.get("sack", True):
            options.append(('SAckOK', b''))
            
        # Window Scale
        if "wscale" in self.tcp_options_data:
            options.append(('WScale', self.tcp_options_data["wscale"]))
            
        # Timestamp (極為重要)
        if self.tcp_options_data.get("timestamp", True):
            options.append(('Timestamp', (random.randint(100000, 900000), ts_echo)))
            
        return options

    def os_deceive(self, timeout_minutes=5):
        logging.info(f"🚦 Starting OS deception for: {self.os.upper()}")
        
        # 預加載模板到內存，提升速度
        templates = {ptype: self.load_file(ptype) for ptype in ["tcp", "icmp", "udp", "arp"]}
        timeout = datetime.now() + timedelta(minutes=timeout_minutes)

        while datetime.now() < timeout:
            try:
                # 接收封包
                raw, addr = self.conn.sock.recvfrom(65535)
                pkt = Packet(raw)
                pkt.interface = self.nic
                pkt.unpack()

                proto = pkt.l4 if pkt.l4 else pkt.l3
                src_ip = pkt.l3_field.get("src_IP_str")
                
                # ... (JA3 和 Custom Rules 邏輯保持不變) ...
                
                # --- Template Match ---
                key, _ = gen_key(proto, pkt.packet)
                template = templates.get(proto, {}).get(key)
                
                if template:
                    # 使用優化後的 TCP 選項產生回應
                    response = synthesize_response(pkt, template, ttl=self.ttl, window=self.window, deceiver=self)
                    if response:
                        self.conn.sock.send(response)
                        self.sent_packets.append(response)
                        self.protocol_stats[proto.upper()] += 1
                else:
                    # 主動發送 RST 或 ICMP，模擬 closed port
                    if proto == "udp":
                        self.send_icmp_port_unreachable(pkt)
                    elif proto == "tcp":
                        self.send_tcp_rst(pkt)

            except Exception as e:
                logging.debug(f"⚠️ Packets processing error: {e}")

        self.export_data()

    def send_tcp_rst(self, pkt):
        """產生偽造的 RST 封包，騙過 nmap"""
        ip_flags = "DF" if self.os_flags["df"] else None
        
        # 建立 IP 層
        ip = IP(
            src=pkt.l3_field["dest_IP_str"], 
            dst=pkt.l3_field["src_IP_str"], 
            ttl=self.ttl,
            tos=self.os_flags["tos"],
            flags=ip_flags
        )
        
        # 建立 TCP 層，包含特定的 Options
        tcp = TCP(
            sport=pkt.l4_field["dest_port"], 
            dport=pkt.l4_field["src_port"], 
            flags="R", 
            window=self.window,
            options=self.get_tcp_options()
        )
        
        rst = Ether(src=self.mac) / ip / tcp
        self.conn.sock.send(bytes(rst))
        self.sent_packets.append(bytes(rst))
        self.protocol_stats["TCP"] += 1

    def send_icmp_port_unreachable(self, pkt):
        """產生偽造的 ICMP Port Unreachable，騙過 nmap"""
        ip = IP(
            src=pkt.l3_field["dest_IP_str"], 
            dst=pkt.l3_field["src_IP_str"], 
            ttl=self.ttl,
            tos=self.os_flags["tos"]
        )
        icmp = ICMP(type=3, code=3)
        # 嚴格構造被引用的封包內容
        inner = IP(pkt.packet[14:34]) / UDP(pkt.packet[34:42])
        reply = Ether(src=self.mac) / ip / icmp / bytes(inner)[:28]
        
        self.conn.sock.send(bytes(reply))
        self.sent_packets.append(bytes(reply))
        self.protocol_stats["ICMP"] += 1

    # ... (load_file 和 export 邏輯保持不變) ...
