import os
import json
import time
import socket
import random
import logging
from datetime import datetime, timedelta
from collections import defaultdict
from scapy.all import IP, TCP, UDP, ICMP, Ether, wrpcap, get_if_addr, sendp

# 導入專案內部組件
from src.settings import get_os_fingerprint, get_mac_address
from src.Packet import Packet
from src.tcp import TcpConnect
from src.response import synthesize_response
from src.fingerprint_utils import gen_key

class OsDeceiver:
    def __init__(self, target_host, target_os, dest=None, nic=None):
        """
        初始化作業系統欺騙引擎，載入對應的作業系統模板與指紋數據。
        """
        self.nic = nic
        self.mac = get_mac_address(nic) [27]
        self.host = target_host
        self.os = target_os.lower()
        
        # 設定指紋存儲與讀取路徑
        self.dest = dest or os.path.join("os_record", self.os) [2]
        os.makedirs(self.dest, exist_ok=True)
        
        # 初始化原始套接字連接
        self.conn = TcpConnect(self.host, nic=self.nic) [28]
        
        # --- 載入作業系統模板配置 ---
        os_template = get_os_fingerprint(self.os) [23-26]
        self.ttl = os_template.get("ttl", 64)
        self.window = os_template.get("window", 8192)
        self.tcp_options_data = os_template.get("tcp_options", [])
        
        # IPID 配置 (模擬不同 OS 的行為)
        self.ipid_mode = os_template.get("ipid", "increment") [5]
        self.current_ipid = random.randint(1000, 60000)
        self.os_flags = {
            "df": os_template.get("df", False),
            "tos": os_template.get("tos", 0),
        }

        # --- 預先載入指紋模板文件 (從 ts 模式學習而來) ---
        self.templates = {
            ptype: self.load_template_file(ptype) 
            for ptype in ["tcp", "icmp", "udp", "arp"]
        }
        
        self.sent_packets = []
        self.protocol_stats = defaultdict(int)
        self.start_time = time.time() [6]

    def load_template_file(self, ptype):
        """從 os_record 目錄中動態恢復學習到的指紋模板 [4]"""
        filepath = os.path.join(self.dest, f"{ptype}_record.txt")
        if os.path.exists(filepath):
            try:
                with open(filepath, 'r') as f:
                    data = json.load(f)
                    # 將 Hex 字串金鑰轉換回 bytes 以供匹配
                    return {bytes.fromhex(k): bytes.fromhex(v) for k, v in data.items() if v}
            except Exception as e:
                logging.error(f"❌ 解析指紋模板失敗 {filepath}: {e}")
        return {}

    def _get_ipid(self):
        """根據目標 OS 配置計算 IPID [5]"""
        if self.ipid_mode == "random":
            return random.randint(1, 65535)
        elif self.ipid_mode == "zero":
            return 0
        else: # increment
            self.current_ipid = (self.current_ipid + 1) % 65535
            return self.current_ipid

    def process_single_packet(self, pkt_obj, proto, key):
        """
        核心處理函數：接收 main.py 傳來的單個封包，決定回應方式。
        此函數解決了 main.py 調用缺失的問題。
        """
        try:
            # 1. 嘗試匹配學習到的指紋模板
            template_packet = self.templates.get(proto.lower(), {}).get(key)
            
            if template_packet:
                # 使用合成引擎產生回應 [9, 16]
                response = synthesize_response(
                    pkt_obj, template_packet, 
                    ttl=self.ttl, window=self.window, deceiver=self
                )
                if response:
                    out_pkt = Ether(response) if isinstance(response, bytes) else response
                    self._send_packet(out_pkt)
                    self.protocol_stats[proto.upper()] += 1
                    return

            # 2. 如果沒有匹配模板，執行預設的欺騙行為 (Defensive Spoofing)
            if proto.lower() == "udp":
                self.send_icmp_port_unreachable(pkt_obj) [13]
            elif proto.lower() == "tcp":
                self.send_tcp_rst(pkt_obj) [11]
                
        except Exception as e:
            logging.debug(f"⚠️ 單個封包處理失敗: {e}")

    def send_tcp_rst(self, pkt):
        """構建並注入符合目標 OS 特徵的 TCP RST 封包 [11, 12]"""
        dst_mac = pkt.l2_field.get("sMAC", "ff:ff:ff:ff:ff:ff")
        ip_flags = "DF" if self.os_flags["df"] else None
        
        ip = IP(
            src=pkt.l3_field.get("dest_IP_str"),
            dst=pkt.l3_field.get("src_IP_str"),
            ttl=self.ttl,
            tos=self.os_flags["tos"],
            flags=ip_flags,
            id=self._get_ipid()
        )
        
        tcp = TCP(
            sport=pkt.l4_field.get("dest_port", 0),
            dport=pkt.l4_field.get("src_port", 0),
            flags="R",
            window=self.window,
            seq=pkt.l4_field.get("ack_num", 0),
            ack=0
        )
        
        rst = Ether(src=self.mac, dst=dst_mac) / ip / tcp
        self._send_packet(rst)
        self.protocol_stats["TCP_RST"] += 1

    def send_icmp_port_unreachable(self, pkt):
        """構建 RFC 標準的 ICMP 埠號不可達回應 [13-15]"""
        dst_mac = pkt.l2_field.get("sMAC", "ff:ff:ff:ff:ff:ff")
        
        ip = IP(
            src=pkt.l3_field.get("dest_IP_str"),
            dst=pkt.l3_field.get("src_IP_str"),
            ttl=self.ttl,
            id=self._get_ipid()
        )
        
        icmp = ICMP(type=3, code=3)
        # 引用原始封包的部分內容 (L3 header + 8 bytes payload)
        l2_len = len(pkt.l2_header) if pkt.l2_header else 14
        inner_payload = pkt.packet[l2_len:]
        
        reply = Ether(src=self.mac, dst=dst_mac) / ip / icmp / bytes(inner_payload)[:28]
        self._send_packet(reply)
        self.protocol_stats["ICMP_UNREACHABLE"] += 1

    def _send_packet(self, packet):
        """繞過內核協議棧，直接向網卡注入封包 [7]"""
        try:
            sendp(packet, iface=self.nic, verbose=False)
            self.sent_packets.append(bytes(packet))
        except Exception as e:
            logging.error(f"❌ 封包注入失敗: {e}")

    def export_data(self):
        """儲存欺騙工作階段的統計數據 [15]"""
        logging.info(f"📊 欺騙統計: {dict(self.protocol_stats)}")
        pcap_path = os.path.join(self.dest, "deception_responses.pcap")
        if self.sent_packets:
            wrpcap(pcap_path, self.sent_packets)
            logging.info(f"📦 回應封包已儲存至: {pcap_path}")
