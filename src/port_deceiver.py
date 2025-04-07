import os
import time
import json
import random
import logging
import threading
import matplotlib.pyplot as plt
import matplotlib.animation as animation
from collections import defaultdict
from datetime import datetime
from scapy.all import IP, TCP, UDP, ICMP, Ether, send, sniff, wrpcap, get_if_hwaddr

import src.settings as settings
from src.settings import CUSTOM_RULES, get_os_fingerprint

logger = logging.getLogger(__name__)

class PortDeceiver:
    def __init__(self, interface_ip, os_name=None, ports_config=None, nic=None, mac=None):
        self.local_ip = interface_ip
        self.nic = nic or settings.NIC_PROBE
        self.local_mac = mac or get_if_hwaddr(self.nic)
        self.os_name = os_name
        self.ports_config = ports_config or {}

        self.record_path = os.path.join(settings.OS_RECORD_PATH, os_name or "unknown")
        os.makedirs(self.record_path, exist_ok=True)

        fingerprint = get_os_fingerprint(self.os_name) if self.os_name else {}
        self.default_ttl = fingerprint.get('ttl', 64)
        self.default_window = fingerprint.get('window', 8192)
        self.df_flag = fingerprint.get('df', False)
        self.win_scale = fingerprint.get('wscale', 0)
        self.mss_value = fingerprint.get('mss', 1460)
        self.timestamp_enabled = fingerprint.get('timestamp', False) or fingerprint.get('ts', False)

        self.protocol_stats = defaultdict(int)
        self.sent_packets = []
        self.session_log = {}

        self._init_plot()

    def _init_plot(self):
        self.fig, self.ax = plt.subplots()
        self.ani = animation.FuncAnimation(self.fig, self._update_plot, interval=1000)
        threading.Thread(target=plt.show, daemon=True).start()

    def _update_plot(self, frame):
        self.ax.clear()
        labels = list(self.protocol_stats.keys())
        values = [self.protocol_stats[k] for k in labels]
        self.ax.bar(labels, values)
        self.ax.set_title("Port Deception Live Stats")
        self.ax.set_ylabel("Packets Sent")
        self.ax.set_ylim(0, max(values + [1]))

    def run(self):
        def _handler(pkt):
            if pkt.haslayer(IP) and pkt[IP].dst == self.local_ip:
                ip = pkt[IP]
                response = None
                proto = None

                if pkt.haslayer(TCP):
                    tcp = pkt[TCP]
                    proto = "tcp"
                    flags = tcp.flags
                    dport = tcp.dport
                elif pkt.haslayer(UDP):
                    udp = pkt[UDP]
                    proto = "udp"
                    dport = udp.dport
                elif pkt.haslayer(ICMP):
                    icmp = pkt[ICMP]
                    if icmp.type == 8:
                        proto = "icmp"
                        dport = 0
                else:
                    return

                # Check custom rules
                for rule in CUSTOM_RULES:
                    match = rule.get("proto", "").lower() == proto
                    match &= rule.get("port", dport) == dport if "port" in rule else True
                    match &= rule.get("flags", "") == str(flags) if proto == "tcp" and "flags" in rule else True
                    match &= rule.get("action", "") in ["drop", "rst", "icmp_unreachable", "template"]

                    if match:
                        logger.info(rule.get("log", f"Matched rule on port {dport}"))
                        if rule["action"] == "drop":
                            return
                        elif rule["action"] == "rst" and proto == "tcp":
                            response = self.build_tcp_rst(ip.src, tcp.sport, dport)
                            break
                        elif rule["action"] == "icmp_unreachable" and proto == "udp":
                            response = self.build_icmp_unreachable(ip, pkt)
                            break

                if not response:
                    response = self.craft_response(ip, pkt, proto)

                if response:
                    send(response, verbose=False)
                    self.sent_packets.append(response)
                    self.protocol_stats[proto.upper()] += 1

        logger.info(f"🚀 PortDeceiver running on NIC: {self.nic} | IP: {self.local_ip} | MAC: {self.local_mac}")
        try:
            sniff(iface=self.nic, filter=f"ip host {self.local_ip}", prn=_handler, store=False)
        except Exception as e:
            logger.error(f"❌ Error in PortDeceiver: {e}")
        finally:
            self.export_logs()

    def craft_response(self, ip, pkt, proto):
        now = datetime.utcnow().isoformat()
        dport = pkt[TCP].dport if proto == "tcp" else pkt[UDP].dport
        state = self.ports_config.get(dport, "closed")

        ether = Ether(src=self.local_mac, dst=pkt[Ether].src)
        ip_layer = IP(src=self.local_ip, dst=ip.src, ttl=self.default_ttl)
        if self.df_flag:
            ip_layer.flags = "DF"

        if proto == "tcp" and pkt.haslayer(TCP):
            flags = "SA" if state == "open" else "R"
            tcp_layer = TCP(sport=dport, dport=pkt[TCP].sport, flags=flags, window=self.default_window)
            opts = []
            if self.mss_value:
                opts.append(('MSS', self.mss_value))
            if self.win_scale:
                opts.append(('WScale', self.win_scale))
            if self.timestamp_enabled:
                ts_val = int(time.time() * 1000) & 0xFFFFFFFF
                opts.append(('Timestamp', (ts_val, 0)))
                opts.append(('SAckOK', ''))
            tcp_layer.options = self.fuzz_tcp_options(opts)

            self.session_log[ip.src] = {"proto": "TCP", "port": dport, "state": state, "time": now}
            return ether / ip_layer / tcp_layer

        elif proto == "udp" and pkt.haslayer(UDP):
            if state == "closed":
                return self.build_icmp_unreachable(ip, pkt)
            udp_layer = UDP(sport=dport, dport=pkt[UDP].sport)
            self.session_log[ip.src] = {"proto": "UDP", "port": dport, "state": state, "time": now}
            return ether / ip_layer / udp_layer

        elif proto == "icmp":
            icmp_reply = ICMP(type=0)
            self.session_log[ip.src] = {"proto": "ICMP", "state": "reply", "time": now}
            return ether / ip_layer / icmp_reply

        return None

    def build_tcp_rst(self, src_ip, sport, dport):
        ether = Ether(src=self.local_mac)
        ip = IP(src=self.local_ip, dst=src_ip, ttl=self.default_ttl)
        tcp = TCP(sport=dport, dport=sport, flags="R")
        return ether / ip / tcp

    def build_icmp_unreachable(self, ip, pkt):
        inner = IP(pkt[IP]) / UDP(pkt[UDP])
        icmp = ICMP(type=3, code=3)
        return Ether(src=self.local_mac) / IP(src=self.local_ip, dst=ip.src, ttl=self.default_ttl) / icmp / bytes(inner)[:28]

    def fuzz_tcp_options(self, options):
        if random.random() < 0.2:
            random.shuffle(options)
        if random.random() < 0.1 and options:
            options = options[:-1]
        return options

    def export_logs(self):
        try:
            wrpcap(os.path.join(self.record_path, "sent_port_responses.pcap"), self.sent_packets)
            logger.info("📦 PortDeceiver PCAP saved.")
        except Exception as e:
            logger.warning(f"⚠ Failed to write PCAP: {e}")

        try:
            with open(os.path.join(self.record_path, "port_session_log.json"), "w") as f:
                json.dump(self.session_log, f, indent=2)
            logger.info("📝 PortDeceiver session log saved.")
        except Exception as e:
            logger.warning(f"⚠ Failed to write session log: {e}")
