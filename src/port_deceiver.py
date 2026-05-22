import os
import json
import csv
import logging
from datetime import datetime
from scapy.all import sniff, Ether, IP, TCP, UDP, ICMP, wrpcap

from src.settings import CUSTOM_RULES, JA3_RULES, get_os_fingerprint
from src.response import synthesize_response
from src.Packet import Packet
from src.tcp import TcpConnect
from src.ja3_extractor import extract_ja3, match_ja3_rule
from src import l7_tracker

class PortDeceiver:
    def __init__(self, interface_ip, os_name, ports_config, nic, mac=None, replay=False, interactive=False, enable_dns=False, enable_tls=False):
        self.interface_ip = interface_ip
        self.os_name = os_name
        self.ports_config = ports_config
        self.nic = nic
        self.mac = mac
        self.replay = replay
        self.interactive = interactive
        self.enable_dns = enable_dns
        self.enable_tls = enable_tls

        self.fingerprint = get_os_fingerprint(os_name)
        self.ttl = self.fingerprint.get("ttl", 64)
        self.window = self.fingerprint.get("window", 8192)
        self.os_flags = {
            "df": self.fingerprint.get("df", False),
            "tos": self.fingerprint.get("tos", 0),
            "ecn": self.fingerprint.get("ecn", 0),
            "reserved": self.fingerprint.get("tcp_reserved", 0),
            "ip_options": self.fingerprint.get("ip_options", b"")
        }

        self.conn = TcpConnect(self.interface_ip, nic=self.nic)
        self.protocol_stats = {}
        self.session_log = {}
        self.ja3_log = {}
        self.sent_packets = []

        l7_tracker.launch_plot()

    def run(self):
        logging.info(f"🚦 Starting active port deception engine on {self.nic} (IP: {self.interface_ip})")
        try:
            sniff(iface=self.nic, prn=self._handle_packet, store=False)
        finally:
            self._export_logs()

    def _handle_packet(self, pkt_raw):
        try:
            pkt = Packet(bytes(pkt_raw))
            pkt.interface = self.nic
            pkt.unpack()
            
            # Prevent loopback echo processing from tracking self-generated responses
            src_ip = pkt.l3_field.get("src_IP_str")
            if src_ip == self.interface_ip:
                return

            proto = pkt.l4
            dst_ip = pkt.l3_field.get("dest_IP_str")
            dst_port = pkt.l4_field.get("dest_port")
            raw_flags = pkt.l4_field.get("flags", 0)
            tos = pkt.l3_field.get("TYPE_OF_SERVICE", 0)
            ja3_hash = None
            user_agent = None

            # 1. TLS/JA3 Inspection Handler Logic
            if proto == "tcp" and dst_port == 443:
                ja3_hash = extract_ja3(pkt.packet)
                if ja3_hash:
                    self.ja3_log.setdefault(src_ip, []).append(ja3_hash)
                    logging.info(f"🔍 TLS Session Fingerprint for {src_ip}: {ja3_hash}")
                    matched_rule = match_ja3_rule(ja3_hash)
                    if matched_rule:
                        action = matched_rule.get("action")
                        if action == "drop":
                            logging.info(matched_rule.get("log", f"❌ Dropping connection via JA3 blocklist: {ja3_hash}"))
                            return
                        elif action == "template":
                            logging.info(matched_rule.get("log", f"📦 Matching JA3 to template target: {matched_rule.get('template_name')}"))

            # 2. L7 Banner Tracker Normalizer Rules
            if proto == "tcp" and dst_port in [80, 8080]:
                payload = pkt.l4_field.get("raw_payload", b"").decode(errors="ignore")
                if payload.startswith("GET"):
                    for line in payload.split("\r\n"):
                        if line.lower().startswith("user-agent"):
                            user_agent = line.split(":", 1)[-1].strip().lower()
                            break
                    banner_type = "curl" if "curl" in (user_agent or "") else "chrome" if "chrome" in (user_agent or "") else "default"
                    l7_tracker.log_http_banner(src_ip, ja3_hash, banner_type, user_agent)

            # 3. Custom Firewalls / Routing Rule Enforcement Matching Engine
            for rule in CUSTOM_RULES:
                match = rule.get("proto", "").lower() == proto
                match &= rule.get("port", dst_port) == dst_port if "port" in rule else True
                
                # FIXED: Translate flag bitmasks safely to their corresponding standard string tokens
                if proto == "tcp" and "flags" in rule:
                    flag_string_map = {0x01: "F", 0x02: "S", 0x04: "R", 0x08: "P", 0x10: "A"}
                    current_flag_char = flag_string_map.get(raw_flags & 0x1F, "")
                    match &= rule.get("flags") == current_flag_char
                
                match &= rule.get("type") == pkt.l4_field.get("icmp_type") if proto == "icmp" else True
                match &= rule.get("dscp", -1) == (tos >> 2) if "dscp" in rule else True
                match &= rule.get("src_ip", "") == src_ip if "src_ip" in rule else True
                
                if match:
                    logging.info(rule.get("log", f"Custom interception rule hit on standard stack protocol: {proto.upper()}:{dst_port}"))
                    if rule["action"] == "drop":
                        return
                    elif rule["action"] == "rst" and proto == "tcp":
                        self._send_rst(pkt)
                        return
                    elif rule["action"] == "icmp_unreachable" and proto == "udp":
                        self._send_icmp_unreachable(pkt)
                        return
                    elif rule["action"] == "template":
                        break

            # FIXED: Avoid parsing empty baseline bytes. Fall back gracefully to pristine state packet builders.
            response = synthesize_response(pkt, template_bytes=None, ttl=self.ttl, window=self.window, deceiver=self)
            if response:
                # Convert raw byte payloads into valid Scapy Link-Layer frame objects
                out_frame = Ether(response) if isinstance(response, bytes) else response
                self.conn.send_packet(bytes(out_frame))
                self.sent_packets.append(bytes(out_frame))
                
                self.session_log.setdefault(src_ip, []).append({
                    "proto": proto,
                    "port": dst_port,
                    "ja3": ja3_hash,
                    "ua": user_agent,
                    "time": datetime.utcnow().isoformat()
                })

        except Exception as e:
            logging.warning(f"⚠️ PortDeceiver core packet loop exception error: {e}")

    def _send_rst(self, pkt):
        """Constructs and injects a tailored TCP RST signature packet safely"""
        rst = self.conn.build_tcp_rst(pkt, ttl=self.ttl)
        if rst:
            out_frame = Ether(rst) if isinstance(rst, bytes) else rst
            self.conn.send_packet(bytes(out_frame))
            self.sent_packets.append(bytes(out_frame))
            self.protocol_stats["RST"] = self.protocol_stats.get("RST", 0) + 1

    def _send_icmp_unreachable(self, pkt):
        """Constructs an accurate RFC-compliant ICMP Destination Unreachable response"""
        # Extract source hardware components safely from incoming parsed dictionaries
        target_mac = pkt.l2_field.get("sMAC", "ff:ff:ff:ff:ff:ff")
        
        ip = IP(src=pkt.l3_field.get("dest_IP_str"), dst=pkt.l3_field.get("src_IP_str"), ttl=self.ttl, tos=self.os_flags["tos"])
        icmp = ICMP(type=3, code=3)
        
        # FIXED: Extract nested network headers dynamically via Scapy's native layout decoder maps
        raw_scapy = Ether(pkt.packet)
        if raw_scapy.haslayer(IP):
            inner_quote = raw_scapy[IP].copy()
            # Truncate optional transport payloads to stay within default safety guidelines
            del inner_quote.chksum
            if inner_quote.haslayer(TCP):
                del inner_quote[TCP].chksum
            elif inner_quote.haslayer(UDP):
                del inner_quote[UDP].chksum
                
            response = Ether(src=self.mac, dst=target_mac) / ip / icmp / bytes(inner_quote)[:28]
            self.conn.send_packet(bytes(response))
            self.sent_packets.append(bytes(response))
            self.protocol_stats["ICMP"] = self.protocol_stats.get("ICMP", 0) + 1

    def _export_logs(self):
        """Saves session database details across unified formats upon engine teardown."""
        base = os.path.join("os_record", self.os_name)
        os.makedirs(base, exist_ok=True)

        json_path = os.path.join(base, "port_sessions.json")
        csv_path = os.path.join(base, "port_sessions.csv")
        pcap_path = os.path.join(base, "port_responses.pcap")

        try:
            with open(json_path, "w") as f:
                json.dump(self.session_log, f, indent=2)
            logging.info(f"📝 Session log saved → {json_path}")
        except Exception as e:
            logging.warning(f"⚠️ Failed to save session JSON: {e}")

        try:
            with open(csv_path, "w", newline='') as f:
                writer = csv.writer(f)
                writer.writerow(["src_ip", "proto", "port", "ja3", "user_agent", "time"])
                for ip, entries in self.session_log.items():
                    for entry in entries:
                        writer.writerow([ip, entry.get("proto"), entry.get("port"), entry.get("ja3"), entry.get("ua"), entry.get("time")])
            logging.info(f"📄 Session CSV saved → {csv_path}")
        except Exception as e:
            logging.warning(f"⚠️ Failed to save session CSV: {e}")

        try:
            wrpcap(pcap_path, self.sent_packets)
            logging.info(f"📦 Response PCAP saved → {pcap_path}")
        except Exception as e:
            logging.warning(f"⚠️ Failed to save PCAP: {e}")
