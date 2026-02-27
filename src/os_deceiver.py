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
        
        # --- 核心優化：加載 OS 指紋配置 ---
        os_template = get_os_fingerprint(self.os)
        self.ttl = os_template.get("ttl", 64)
        self.window = os_template.get("window", 8192)
        self.tcp_options_data = os_template.get("tcp_options", {}) 
        
        # IPID 模式: "increment", "random", "zero"
        self.ipid_mode = os_template.get("ipid", "increment")
        self.current_ipid = random.randint(1000, 60000)

        self.os_flags = {
            "df": os_template.get("df", False),
            "tos": os_template.get("tos", 0),
            "ecn": os_template.get("ecn", 0),
        }

        self.sent_packets = []
        self.protocol_stats = defaultdict(int)
        
        # 簡單的 Timestamp 計算器
        self.start_time = time.time()

    def _get_ipid(self):
        """根據配置模式獲取 IPID"""
        if self.ipid_mode == "random":
            return random.randint(1, 65535)
        elif self.ipid_mode == "zero":
            return 0
        else: # increment
            self.current_ipid = (self.current_ipid + 1) % 65535
            return self.current_ipid

    def _get_timestamp_val(self):
        """產生反映系統uptime的Timestamp值"""
        return int((time.time() - self.start_time) * 100) # 每10ms增加1

    def get_tcp_options(self, ts_echo=0):
        """根據 OS 特徵產生精確的 TCP SYN/ACK 選項。"""
        options = []
        # MSS
        options.append(('MSS', self.tcp_options_data.get("mss", 1460)))
        
        # SackOK
        if self.tcp_options_data.get("sack", True):
            options.append(('SAckOK', b''))
            
        # Window Scale
        if "wscale" in self.tcp_options_data:
            options.append(('WScale', self.tcp_options_data["wscale"]))
            
        # Timestamp
        if self.tcp_options_data.get("timestamp", True):
            options.append(('Timestamp', (self._get_timestamp_val(), ts_echo)))
            
        return options

    def _send_packet(self, packet):
        """封裝後的封包發送邏輯"""
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
                src_ip = pkt.l3_field.get("src_IP_str")
                
                # --- L7 & JA3 Logic (保持原本邏輯) ---
                
                # --- Template Match ---
                key, _ = gen_key(proto, pkt.packet)
                template = templates.get(proto, {}).get(key)
                
                if template:
                    response = synthesize_response(pkt, template, ttl=self.ttl, window=self.window, deceiver=self)
                    if response:
                        self._send_packet(Ether(response))
                        self.protocol_stats[proto.upper()] += 1
                else:
                    # 主動回應 Closed Port
                    if proto == "udp":
                        self.send_icmp_port_unreachable(pkt)
                    elif proto == "tcp":
                        self.send_tcp_rst(pkt)

            except Exception as e:
                logging.debug(f"⚠️ Packet processing error: {e}")

        self.export_data()

    def send_tcp_rst(self, pkt):
        """產生偽造的 RST 封包"""
        ip_flags = "DF" if self.os_flags["df"] else None
        
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
        
        rst = Ether(src=self.mac) / ip / tcp
        self._send_packet(rst)
        self.protocol_stats["TCP"] += 1

    def send_icmp_port_unreachable(self, pkt):
        """產生偽造的 ICMP Port Unreachable"""
        ip = IP(
            src=pkt.l3_field["dest_IP_str"], 
            dst=pkt.l3_field["src_IP_str"], 
            ttl=self.ttl,
            tos=self.os_flags["tos"],
            id=self._get_ipid()
        )
        icmp = ICMP(type=3, code=3)
        # 嚴格構造被引用的封包內容
        inner = IP(pkt.packet[14:34]) / UDP(pkt.packet[34:42])
        reply = Ether(src=self.mac) / ip / icmp / bytes(inner)[:28]
        
        self._send_packet(reply)
        self.protocol_stats["ICMP"] += 1

    # ... (load_file 和 export 邏輯保持不變) ...
