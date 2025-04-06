import logging
import random
import time
from scapy.all import IP, TCP, UDP, ICMP, send, sniff
from settings import get_os_fingerprint

logger = logging.getLogger(__name__)

class PortDeceiver:
    def __init__(self, interface_ip, os_name=None, ports_config=None):
        self.local_ip = interface_ip
        self.os_name = os_name
        self.ports_config = ports_config or {}

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
            return ip_layer / tcp_layer

        elif proto == 'icmp':
            ip_layer = IP(src=self.local_ip, dst=src_ip, ttl=self.default_ttl)
            return ip_layer / ICMP(type=0)

        elif proto == 'udp':
            ip_layer = IP(src=self.local_ip, dst=src_ip, ttl=self.default_ttl)
            return ip_layer / UDP(sport=dst_port, dport=src_port)

        return None

    def simulate_timing(self, port):
        if self.ports_config.get(port, 'closed') == 'open':
            return random.uniform(0.005, 0.030)
        else:
            return random.uniform(0.050, 0.150)

    def fuzz_tcp_options(self, options):
        if random.random() < 0.2:
            random.shuffle(options)
        if random.random() < 0.1:
            options = options[:-1]  # randomly drop last option
        return options

    def run(self):
        def _packet_handler(packet):
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

        try:
            sniff(filter=f"ip host {self.local_ip}", prn=_packet_handler, store=False)
        except Exception as e:
            logger.error(f"PortDeceiver sniffing error: {e}")
