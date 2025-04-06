import os
import json
import time
import random
import logging
import threading
import base64
from datetime import datetime
from collections import defaultdict
import matplotlib.pyplot as plt
import matplotlib.animation as animation
from scapy.all import Ether, IP, TCP, UDP, ICMP, send, sniff, wrpcap, get_if_hwaddr

from src.settings import get_os_fingerprint, OS_RECORD_PATH, CUSTOM_RULES

logger = logging.getLogger(__name__)

class PortDeceiver:
    def __init__(self, interface_ip, nic, os_name=None, ports_config=None, mac=None, replay_mode=False):
        self.local_ip = interface_ip
        self.nic = nic
        self.local_mac = mac or get_if_hwaddr(nic)
        self.os_name = os_name
        self.ports_config = ports_config or {}
        self.record_path = os.path.join(OS_RECORD_PATH, os_name or "unknown")
        self.replay_mode = replay_mode

        os.makedirs(self.record_path, exist_ok=True)

        fingerprint = get_os_fingerprint(self.os_name) if self.os_name else {}
        if not fingerprint:
            logger.warning("⚠ Using fallback TTL=64, window=8192.")
            fingerprint = {'ttl': 64, 'window': 8192}

        self.default_ttl = fingerprint.get('ttl', 64)
        self.default_window = fingerprint.get('window', 8192)
        self.df_flag = fingerprint.get('df', False)
        self.win_scale = fingerprint.get('wscale', 0)
        self.mss_value = fingerprint.get('mss', 1460)
        self.timestamp_enabled = fingerprint.get('timestamp', False) or fingerprint.get('ts', False)

        self.protocol_stats = defaultdict(int)
        self.sent_packets = []
        self.session_log = {}

        self.templates = self.load_templates()
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
        self.ax.set_title("Port Deception Stats")
        self.ax.set_ylabel("Sent Packets")
        self.ax.set_ylim(0, max(values + [1]))

    def simulate_timing(self, port):
        return random.uniform(0.005, 0.030) if self.ports_config.get(port) == 'open' else random.uniform(0.050, 0.150)

    def fuzz_tcp_options(self, options):
        if random.random() < 0.2:
            random.shuffle(options)
        if random.random() < 0.1 and options:
            options = options[:-1]
        return options

    def load_templates(self):
        result = {}
        for proto in ['tcp', 'udp', 'icmp']:
            path = os.path.join(self.record_path, f"{proto}_record.txt")
            if not os.path.exists(path):
                continue
            with open(path) as f:
                data = json.load(f)
            result[proto] = {
                base64.b64decode(k): base64.b64decode(v) for k, v in data.items()
            }
        return result

    def check_custom_rules(self, proto, pkt):
        src_ip = pkt[IP].src
        dport = pkt[TCP].dport if proto == 'tcp' else pkt[UDP].dport
        flags = pkt[TCP].flags if proto == 'tcp' else None
        tos = pkt[IP].tos

        for rule in CUSTOM_RULES:
            if rule.get("proto", "").lower() != proto:
                continue
            if rule.get("port") and rule["port"] != dport:
                continue
            if rule.get("flags") and rule["flags"] != flags:
                continue
            if rule.get("src_ip") and rule["src_ip"] != src_ip:
                continue
            if rule.get("dscp") and rule["dscp"] != (tos >> 2):
                continue

            logger.info(rule.get("log", f"✅ Matched {proto.upper()} rule on port {dport}"))
            return rule.get("action")

        return None

    def build_response(self, proto, pkt):
        if self.replay_mode:
            logger.info("🔁 Replay mode enabled — template responses coming soon.")
            return None  # Stub for replay mode

        src_ip = pkt[IP].src
        dst_port = pkt[TCP].dport if proto == 'tcp' else pkt[UDP].dport
        src_port = pkt[TCP].sport if proto == 'tcp' else pkt[UDP].sport

        ether = Ether(src=self.local_mac, dst=pkt[Ether].src)
        ip = IP(src=self.local_ip, dst=src_ip, ttl=self.default_ttl)
        if self.df_flag:
            ip.flags |= 0x2

        now = datetime.utcnow().isoformat()
        key = f"{src_ip}:{src_port}->{dst_port}"

        if proto == 'tcp':
            state = self.ports_config.get(dst_port, 'closed')
            tcp = TCP(sport=dst_port, dport=src_port, flags='SA' if state == 'open' else 'R', window=self.default_window)
            options = [('MSS', self.mss_value), ('WScale', self.win_scale), ('Timestamp', (int(time.time()*1000), 0))]
            tcp.options = self.fuzz_tcp_options(options)
            self.session_log[key] = {"state": state, "time": now, "proto": proto}
            return ether / ip / tcp

        elif proto == 'udp':
            state = self.ports_config.get(dst_port, 'closed')
            if state == 'closed':
                icmp = ICMP(type=3, code=3)
                udp_layer = pkt[UDP]
                return ether / ip / icmp / IP(bytes(pkt[IP])) / udp_layer
            else:
                udp = UDP(sport=dst_port, dport=src_port)
                return ether / ip / udp

        elif proto == 'icmp':
            icmp = ICMP(type=0)
            return ether / ip / icmp

        return None

    def run(self):
        def _handler(pkt):
            if not pkt.haslayer(IP):
                return
            if pkt[IP].dst != self.local_ip:
                return

            response = None

            if pkt.haslayer(TCP):
                action = self.check_custom_rules('tcp', pkt)
                if action == 'drop':
                    return
                response = self.build_response('tcp', pkt)
                if response:
                    self.protocol_stats['TCP'] += 1

            elif pkt.haslayer(UDP):
                action = self.check_custom_rules('udp', pkt)
                if action == 'icmp_unreachable':
                    icmp = ICMP(type=3, code=3)
                    ip = IP(src=self.local_ip, dst=pkt[IP].src)
                    ether = Ether(src=self.local_mac, dst=pkt[Ether].src)
                    response = ether / ip / icmp / pkt[IP]
                else:
                    response = self.build_response('udp', pkt)
                if response:
                    self.protocol_stats['UDP'] += 1

            elif pkt.haslayer(ICMP) and pkt[ICMP].type == 8:
                response = self.build_response('icmp', pkt)
                if response:
                    self.protocol_stats['ICMP'] += 1

            if response:
                send(response, verbose=False)
                self.sent_packets.append(response)

        logger.info(f"🚀 PortDeceiver running on {self.nic} | IP: {self.local_ip} | MAC: {self.local_mac}")
        sniff(iface=self.nic, filter=f"ip host {self.local_ip}", prn=_handler, store=False)
        self.export_logs()

    def export_logs(self):
        wrpcap(os.path.join(self.record_path, "sent_port_responses.pcap"), self.sent_packets)
        with open(os.path.join(self.record_path, "session_log.json"), "w") as f:
            json.dump(self.session_log, f, indent=2)
        logger.info(f"📦 Exported PCAP and session log to {self.record_path}")
