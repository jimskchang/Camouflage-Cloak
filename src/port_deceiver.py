import os
import json
import logging
from datetime import datetime
from scapy.all import sniff, Ether, IP, TCP, UDP, ICMP
from src.settings import CUSTOM_RULES, JA3_RULES, get_os_fingerprint
from src.response import synthesize_response, synthesize_tls_server_hello
from src.Packet import Packet
from src.tcp import TcpConnect
from src.ja3_extractor import extract_ja3, match_ja3_rule
from src.fingerprint_utils import gen_key

class PortDeceiver:
    def __init__(self, interface_ip, os_name, ports_config, nic, mac=None, replay=False, interactive=False):
        self.interface_ip = interface_ip
        self.os_name = os_name
        self.ports_config = ports_config
        self.nic = nic
        self.mac = mac
        self.replay = replay
        self.interactive = interactive

        self.fingerprint = get_os_fingerprint(os_name)
        self.ttl = self.fingerprint.get("ttl")
        self.window = self.fingerprint.get("window")
        self.os_flags = {
            "df": self.fingerprint.get("df", False),
            "tos": self.fingerprint.get("tos", 0),
            "ecn": self.fingerprint.get("ecn", 0),
        }

        self.conn = TcpConnect(self.interface_ip, nic=self.nic)
        self.protocol_stats = {}
        self.session_log = {}
        self.ja3_log = {}
        self.sent_tls_templates = {}

    def run(self):
        logging.info(f"🚦 Starting port deception on {self.nic} (IP: {self.interface_ip})")
        try:
            sniff(iface=self.nic, prn=self._handle_packet, store=False)
        finally:
            self.export_logs()

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

            # JA3 detection
            if proto == "tcp" and dst_port == 443:
                ja3_hash = extract_ja3(pkt.packet)
                if ja3_hash:
                    self.ja3_log.setdefault(src_ip, []).append(ja3_hash)
                    logging.info(f"🔍 JA3 for {src_ip}: {ja3_hash}")
                    matched_rule = match_ja3_rule(ja3_hash)
                    if matched_rule:
                        if matched_rule.get("action") == "drop":
                            logging.info(matched_rule.get("log", f"❌ Dropping JA3 {ja3_hash}"))
                            return
                        elif matched_rule.get("action") == "tls_hello":
                            response = synthesize_tls_server_hello(pkt, fuzz_cert=True)
                            self.conn.send_packet(response)
                            self._log_session(src_ip, proto, dst_port, ja3_hash, action="tls_hello")
                            return

            # Custom L3/L4 rule processing
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

            # Default template-based response
            response = synthesize_response(pkt, b"", ttl=self.ttl, window=self.window, deceiver=self)
            if response:
                self.conn.send_packet(response)
                self._log_session(src_ip, proto, dst_port, ja3_hash)

        except Exception as e:
            logging.warning(f"⚠️ PortDeceiver error: {e}")

    def _log_session(self, src_ip, proto, port, ja3_hash=None, action="template"):
        self.session_log.setdefault(src_ip, []).append({
            "proto": proto,
            "port": port,
            "ja3": ja3_hash,
            "action": action,
            "time": datetime.utcnow().isoformat()
        })

    def export_logs(self):
        base_path = os.path.join("os_record", self.os_name.lower())
        os.makedirs(base_path, exist_ok=True)

        if self.ja3_log:
            path = os.path.join(base_path, "ja3_observed.json")
            with open(path, "w") as f:
                json.dump(self.ja3_log, f, indent=2)
            logging.info(f"📁 Exported JA3 logs: {path}")

        if self.session_log:
            path = os.path.join(base_path, "port_session_log.json")
            with open(path, "w") as f:
                json.dump(self.session_log, f, indent=2)
            logging.info(f"📝 Exported Port session logs: {path}")

    def _send_rst(self, pkt):
        rst = self.conn.build_tcp_rst(pkt)
        self.conn.send_packet(rst)
        self.protocol_stats["RST"] = self.protocol_stats.get("RST", 0) + 1

    def _send_icmp_unreachable(self, pkt):
        from scapy.all import ICMP
        ip = IP(src=pkt.l3_field["dest_IP_str"], dst=pkt.l3_field["src_IP_str"])
        icmp = ICMP(type=3, code=3)
        inner = IP(pkt.packet[14:34]) / UDP(pkt.packet[34:42])
        response = Ether(src=self.mac) / ip / icmp / bytes(inner)[:28]
        self.conn.send_packet(bytes(response))
