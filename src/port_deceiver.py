import os
import time
import random
import logging
import threading
import json
from datetime import datetime
from collections import defaultdict
import matplotlib.pyplot as plt
import matplotlib.animation as animation
from scapy.all import IP, TCP, UDP, ICMP, Ether, send, sniff, wrpcap, get_if_hwaddr

from src.settings import get_os_fingerprint, OS_RECORD_PATH, CUSTOM_RULES

logger = logging.getLogger(__name__)

class PortDeceiver:
    def __init__(self, local_ip, nic, os_name=None, ports_config=None, mac=None):
        self.local_ip = local_ip
        self.nic = nic
        self.local_mac = mac or get_if_hwaddr(nic)
        self.os_name = os_name
        self.ports_config = ports_config or {}
        self.record_path = os.path.join(OS_RECORD_PATH, os_name or "unknown")
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
        self.sessions = {}
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
        self.ax.set_title("Live Port Deception Stats")
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

    def apply_custom_rules(self, proto, port, flags=None, dscp=None):
        for rule in CUSTOM_RULES:
            if rule.get("proto", "").upper() != proto.upper():
                continue
            if rule.get("port") and rule["port"] != port:
                continue
            if rule.get("flags") and rule["flags"] != flags:
                continue
            if rule.get("dscp") and rule["dscp"] != dscp:
                continue

            action = rule.get("action", "drop")
            if rule.get("log"):
                logger.info(rule["log"])
            return action
        return None

    def craft_response(self, src_ip, src_port, dst_port, flag, proto='tcp', dscp=None):
        time.sleep(self.simulate_timing(dst_port))
        ether = Ether(src=self.local_mac)
        ip = IP(src=self.local_ip, dst=src_ip, ttl=self.default_ttl, tos=(dscp or 0))
        if self.df_flag:
            ip.flags |= 0x2

        now = datetime.utcnow().isoformat()
        session_key = f"{src_ip}:{src_port}->{dst_port}"

        # Check custom rules
        rule_action = self.apply_custom_rules(proto, dst_port, flag, dscp)
        if rule_action == "drop":
            return None
        elif rule_action == "rst":
            rst = TCP(sport=dst_port, dport=src_port, flags='R', window=self.default_window)
            self.session_log[session_key] = {"state": "rst", "time": now}
            return ether / ip / rst
        elif rule_action == "icmp_unreachable":
            icmp = ICMP(type=3, code=3)
            self.session_log[session_key] = {"state": "icmp-unreachable", "time": now}
            return ether / ip / icmp / (ip / UDP(sport=src_port, dport=dst_port))[:28]

        if proto == 'tcp':
            if flag != 'S':
                return None
            state = self.ports_config.get(dst_port, 'closed')
            tcp = TCP(sport=dst_port, dport=src_port,
                      flags='SA' if state == 'open' else 'R',
                      window=self.default_window)
            options = []
            if self.mss_value:
                options.append(('MSS', self.mss_value))
            if self.win_scale:
                options.append(('WScale', self.win_scale))
            if self.timestamp_enabled:
                ts_val = int(time.time() * 1000) & 0xFFFFFFFF
                options.append(('Timestamp', (ts_val, 0)))
            if self.timestamp_enabled:
                options.append(('SAckOK', ''))
            tcp.options = self.fuzz_tcp_options(options)
            self.session_log[session_key] = {"state": "half-open" if state == 'open' else "rejected", "time": now}
            return ether / ip / tcp

        elif proto == 'udp':
            state = self.ports_config.get(dst_port, 'closed')
            if state == 'closed':
                icmp = ICMP(type=3, code=3)
                self.session_log[session_key] = {"state": "udp-unreachable", "time": now}
                return ether / ip / icmp / (ip / UDP(sport=src_port, dport=dst_port))[:28]
            else:
                udp = UDP(sport=dst_port, dport=src_port)
                self.session_log[session_key] = {"state": "udp-open", "time": now}
                return ether / ip / udp

        elif proto == 'icmp':
            icmp = ICMP(type=0)
            self.session_log[session_key] = {"state": "icmp-echo-reply", "time": now}
            return ether / ip / icmp

        return None

    def run(self):
        def _handler(pkt):
            if pkt.haslayer(IP) and pkt[IP].dst == self.local_ip:
                ip = pkt[IP]
                dscp = ip.tos >> 2
                response = None

                if pkt.haslayer(TCP):
                    tcp = pkt[TCP]
                    flag = tcp.sprintf("%TCP.flags%")
                    response = self.craft_response(ip.src, tcp.sport, tcp.dport, flag, proto='tcp', dscp=dscp)
                    if response:
                        self.protocol_stats["TCP"] += 1
                elif pkt.haslayer(UDP):
                    udp = pkt[UDP]
                    response = self.craft_response(ip.src, udp.sport, udp.dport, 'S', proto='udp', dscp=dscp)
                    if response:
                        self.protocol_stats["UDP"] += 1
                elif pkt.haslayer(ICMP) and pkt[ICMP].type == 8:
                    response = self.craft_response(ip.src, 0, 0, 'S', proto='icmp', dscp=dscp)
                    if response:
                        self.protocol_stats["ICMP"] += 1

                if response:
                    send(response, verbose=False)
                    self.sent_packets.append(response)

        try:
            logger.info(f"🚀 PortDeceiver running on NIC: {self.nic} | IP: {self.local_ip} | MAC: {self.local_mac}")
            sniff(iface=self.nic, filter=f"ip host {self.local_ip}", prn=_handler, store=False)
        except Exception as e:
            logger.error(f"❌ PortDeceiver error: {e}")
        finally:
            self.export_sent_packets()
            self.export_session_log()

    def export_sent_packets(self):
        pcap_path = os.path.join(self.record_path, "sent_port_responses.pcap")
        try:
            wrpcap(pcap_path, self.sent_packets)
            logger.info(f"📦 PortDeceiver saved PCAP to {pcap_path}")
        except Exception as e:
            logger.error(f"❌ Failed to write PCAP: {e}")

    def export_session_log(self):
        log_path = os.path.join(self.record_path, "session_log.json")
        try:
            with open(log_path, "w") as f:
                json.dump(self.session_log, f, indent=2)
            logger.info(f"📝 Exported session log to {log_path}")
        except Exception as e:
            logger.warning(f"⚠ Failed to write session log: {e}")
