# src/port_deceiver.py

import os
import json
import csv
import logging
from datetime import datetime
from scapy.all import sniff, Ether, IP, TCP, UDP, ICMP, wrpcap

from src.settings import CUSTOM_RULES, JA3_RULES, get_os_fingerprint
from src.response import synthesize_response, export_ja3_observed
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
        logging.info(f"🚦 Starting port deception on {self.nic} (IP: {self.interface_ip})")
        sniff(iface=self.nic, prn=self._handle_packet, store=False)
        self._export_logs()

    def _handle_packet(self, pkt_raw):
        try:
            pkt = Packet(bytes(pkt_raw))
            pkt.interface = self.nic
            pkt.unpack()
            proto = pkt.l4
            src_ip = pkt.l3_field.get("src_IP_str")
            dst_ip = pkt.l3_field.get("dest_IP_str")
            dst_port = pkt.l4_field.get("dest_port")
            flags = pkt.l4_field.get("flags", "")
            tos = pkt.l3_field.get("TYPE_OF_SERVICE", 0)
            ja3_hash = None
            user_agent = None

            if proto == "tcp" and dst_port == 443:
                ja3_hash = extract_ja3(pkt.packet)
                if ja3_hash:
                    self.ja3_log.setdefault(src_ip, []).append(ja3_hash)
                    logging.info(f"🔍 JA3 for {src_ip}: {ja3_hash}")
                    matched_rule = match_ja3_rule(ja3_hash)
                    if matched_rule:
                        action = matched_rule.get("action")
                        if action == "drop":
                            logging.info(matched_rule.get("log", f"❌ Dropping JA3 {ja3_hash}"))
                            return
                        elif action == "template":
                            logging.info(matched_rule.get("log", f"📦 JA3 {ja3_hash} → template: {matched_rule.get('template_name')}"))

            if proto == "tcp" and dst_port in [80, 8080]:
                payload = pkt.l4_field.get("raw_payload", b"").decode(errors="ignore")
                if payload.startswith("GET"):
                    for line in payload.split("\r\n"):
                        if line.lower().startswith("user-agent"):
                            user_agent = line.split(":", 1)[-1].strip().lower()
                            break
                    banner_type = "curl" if "curl" in user_agent else "chrome" if "chrome" in user_agent else "default"
                    l7_tracker.log_http_banner(src_ip, ja3_hash, banner_type, user_agent)

            for rule in CUSTOM_RULES:
                match = rule.get("proto", "").lower() == proto
                match &= rule.get("port", dst_port) == dst_port if "port" in rule else True
                match &= rule.get("flags", "") in ["", chr(flags)] if proto == "tcp" else True
                match &= rule.get("type", None) == pkt.l4_field.get("icmp_type") if proto == "icmp" else True
                match &= rule.get("dscp", -1) == (tos >> 2) if "dscp" in rule else True
                match &= rule.get("src_ip", "") == src_ip if "src_ip" in rule else True
                if match:
                    logging.info(rule.get("log", f"Rule matched on {proto.upper()}:{dst_port}"))
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

            response = synthesize_response(pkt, b"", ttl=self.ttl, window=self.window, deceiver=self)
            if response:
                self.conn.send_packet(response)
                self.sent_packets.append(response)
                self.session_log.setdefault(src_ip, []).append({
                    "proto": proto,
                    "port": dst_port,
                    "ja3": ja3_hash,
                    "ua": user_agent,
                    "time": datetime.utcnow().isoformat()
                })

        except Exception as e:
            logging.warning(f"⚠️ PortDeceiver error: {e}")

    def _send_rst(self, pkt):
        rst = self.conn.build_tcp_rst(pkt, ttl=self.ttl)
        self.conn.send_packet(rst)
        self.sent_packets.append(rst)
        self.protocol_stats["RST"] = self.protocol_stats.get("RST", 0) + 1

    def _send_icmp_unreachable(self, pkt):
        ip = IP(src=pkt.l3_field["dest_IP_str"], dst=pkt.l3_field["src_IP_str"], ttl=self.ttl, tos=self.os_flags["tos"])
        icmp = ICMP(type=3, code=3)
        inner = IP(pkt.packet[14:34]) / UDP(pkt.packet[34:42])
        response = Ether(src=self.mac) / ip / icmp / bytes(inner)[:28]
        self.conn.send_packet(bytes(response))
        self.sent_packets.append(bytes(response))
        self.protocol_stats["ICMP"] = self.protocol_stats.get("ICMP", 0) + 1

    def _export_logs(self):
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
