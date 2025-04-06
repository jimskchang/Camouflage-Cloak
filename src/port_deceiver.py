import logging
import random
import time
import threading
import os
import json
from collections import defaultdict
from datetime import datetime
from scapy.all import IP, TCP, UDP, ICMP, send, sniff, wrpcap
import matplotlib.pyplot as plt
import matplotlib.animation as animation

from settings import get_os_fingerprint, check_nic_exists, get_mac_address

logger = logging.getLogger(__name__)

class PortDeceiver:
    def __init__(self, interface_ip, nic, os_name=None, ports_config=None):
        self.local_ip = interface_ip
        self.nic = nic
        self.local_mac = get_mac_address(nic)
        self.os_name = os_name
        self.ports_config = ports_config or {}
        self.sent_packets = []
        self.protocol_stats = defaultdict(int)

        fingerprint = get_os_fingerprint(self.os_name) if self.os_name else {}
        if not fingerprint:
            logger.warning(f"Using fallback TTL=64, window=8192.")
            fingerprint = {'ttl': 64, 'window': 8192}

        self.default_ttl = fingerprint.get('ttl', 64)
        self.default_window = fingerprint.get('window', 8192)
        self.df_flag = fingerprint.get('df', False)
        self.win_scale = fingerprint.get('wscale', 0)
        self.mss_value = fingerprint.get('mss', 1460)
        self.timestamp_enabled = fingerprint.get('timestamp', False) or fingerprint.get('ts', False)
        self.sessions = {}

        logger.info(f"🧬 TTL={self.default_ttl}, Window={self.default_window}, DF={self.df_flag}")
        self._init_plot()

    def _init_plot(self):
        self.fig, self.ax = plt.subplots()
        self.ani = animation.FuncAnimation(self.fig, self._update_plot, interval=1000, blit=False)
        threading.Thread(target=plt.show, daemon=True).start()

    def _update_plot(self, frame):
        self.ax.clear()
        labels = list(self.protocol_stats.keys())
        values = [self.protocol_stats[k] for k in labels]
        self.ax.bar(labels, values)
        self.ax.set_title("Live PortDeceiver Packet Response Count")
        self.ax.set_ylabel("Packets Sent")
        self.ax.set_ylim(0, max(values + [1]))

    def craft_response(self, src_ip, src_port, dst_port, flag, proto='tcp'):
        delay = self.simulate_timing(dst_port)
        time.sleep(delay)

        if proto == 'tcp':
            if flag != 'S':
                return None
            port_state = self.ports_config.get(dst_port, 'closed')
            ip_layer = IP(src=self.local_ip, dst=src_ip, ttl=self.default_ttl)
            if self.df_flag:
                ip_layer.flags |= 0x2
            if port_state == 'open':
                tcp_layer = TCP(sport=dst_port, dport=src_port, flags='SA', window=self.default_window)
            else:
                tcp_layer = TCP(sport=dst_port, dport=src_port, flags='R', window=self.default_window)

            options = []
            if self.mss_value:
                options.append(('MSS', self.mss_value))
            if self.win_scale:
                options.append(('WScale', self.win_scale))
            if self.timestamp_enabled:
                ts_val = int(time.time() * 1000) & 0xFFFFFFFF
                options.append(('Timestamp', (ts_val, 0)))
            if 'MSS' in [opt[0] for opt in options] and self.timestamp_enabled:
                options.append(('SAckOK', ''))

            tcp_layer.options = self.fuzz_tcp_options(options)
            response = ip_layer / tcp_layer
            self.sent_packets.append(response)
            self.protocol_stats["TCP"] += 1
            return response

        elif proto == 'icmp':
            ip_layer = IP(src=self.local_ip, dst=src_ip, ttl=self.default_ttl)
            response = ip_layer / ICMP(type=0)
            self.sent_packets.append(response)
            self.protocol_stats["ICMP"] += 1
            return response

        elif proto == 'udp':
            ip_layer = IP(src=self.local_ip, dst=src_ip, ttl=self.default_ttl)
            response = ip_layer / UDP(sport=dst_port, dport=src_port)
            self.sent_packets.append(response)
            self.protocol_stats["UDP"] += 1
            return response

        return None

    def simulate_timing(self, port):
        return random.uniform(0.005, 0.030) if self.ports_config.get(port, 'closed') == 'open' else random.uniform(0.050, 0.150)

    def fuzz_tcp_options(self, options):
        if random.random() < 0.2:
            random.shuffle(options)
        if random.random() < 0.1 and options:
            options = options[:-1]
        return options

    def run(self):
        def _packet_handler(packet):
            try:
                if packet.haslayer(IP):
                    ip = packet[IP]
                    if ip.dst != self.local_ip:
                        return

                    if packet.haslayer(TCP):
                        tcp = packet[TCP]
                        resp = self.craft_response(ip.src, tcp.sport, tcp.dport, tcp.flags, proto='tcp')
                    elif packet.haslayer(UDP):
                        udp = packet[UDP]
                        resp = self.craft_response(ip.src, udp.sport, udp.dport, 'S', proto='udp')
                    elif packet.haslayer(ICMP):
                        icmp = packet[ICMP]
                        if icmp.type == 8:
                            resp = self.craft_response(ip.src, 0, 0, 'S', proto='icmp')
                    else:
                        resp = None

                    if resp:
                        send(resp, verbose=False)
            except Exception as e:
                logger.warning(f"⚠ Error handling packet: {e}")

        try:
            logger.info("🔍 Starting packet sniffing...")
            sniff(filter=f"ip host {self.local_ip}", iface=self.nic, prn=_packet_handler, store=False)
        except Exception as e:
            logger.error(f"PortDeceiver sniffing error: {e}")
        self.export_sent_packets()

    def export_sent_packets(self):
        try:
            export_path = os.path.join("os_record", f"port_deception_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pcap")
            os.makedirs(os.path.dirname(export_path), exist_ok=True)
            wrpcap(export_path, self.sent_packets)
            logger.info(f"📦 Exported PortDeceiver responses to {export_path}")
        except Exception as e:
            logger.error(f"❌ Failed to export PCAP: {e}")
