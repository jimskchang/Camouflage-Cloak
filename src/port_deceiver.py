"""
port_deceiver.py - Camouflage Cloak Project
Handles TCP port scan deception by responding to probes with OS-specific
network characteristics to mislead reconnaissance tools like Nmap.
"""

import logging
import socket
import struct
import random
import time
import json
import os

import src.settings as settings
from src.tcp import TcpConnect

logger = logging.getLogger(__name__)

class PortDeceiver:
    def __init__(self, target_host: str, nic: str = None, os_name: str = None):
        self.target_host = target_host
        self.nic = nic or settings.NIC_PROBE
        self.os_name = os_name

        tmpl = settings.OS_TEMPLATES.get(os_name, {})
        self.ttl = tmpl.get("ttl", 64)
        self.win = tmpl.get("window", 8192)
        self.ws = tmpl.get("ws", 0)
        self.ip_id_mode = tmpl.get("ip_id_mode", "random")
        self.ip_id_counter = random.randint(0, 65535)

        self.ts_start = time.time()
        self.ip_state = {}  # per-IP scan tracking

        self.os_record_path = os.path.join(settings.OS_RECORD_PATH, self.os_name or "unknown")
        os.makedirs(self.os_record_path, exist_ok=True)

        try:
            self.conn = TcpConnect(self.target_host, nic=self.nic)
        except Exception as e:
            logger.error(f"❌ Failed to initialize TcpConnect on {self.nic}: {e}")
            raise

        logger.info(f"🛡️ PortDeceiver ready on {self.nic} for OS: {self.os_name or 'default'} "
                    f"(TTL={self.ttl}, WIN={self.win}, WS={self.ws}, IP_ID={self.ip_id_mode})")

    def deceive_ps_hs(self, port_status: str = 'open'):
        logger.info(f"🔄 Simulating ports as {'OPEN' if port_status == 'open' else 'CLOSED'}")
        port_flag = 0x12 if port_status == 'open' else 0x14

        try:
            while True:
                packet, addr = self.conn.sock.recvfrom(65565)
                src_ip_str = addr[0]

                if len(packet) < 34:
                    continue

                eth_type = struct.unpack('!H', packet[12:14])[0]
                vlan_offset = 0
                vlan_tag = None

                if eth_type == 0x8100:
                    vlan_tag = struct.unpack('!H', packet[14:16])[0] & 0x0FFF
                    eth_type = struct.unpack('!H', packet[16:18])[0]
                    vlan_offset = 4

                if eth_type != 0x0800:
                    continue

                ip_start = 14 + vlan_offset
                ip_header = packet[ip_start:ip_start + 20]
                iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
                proto = iph[6]
                if proto != 6:
                    continue

                src_ip, dst_ip = iph[8], iph[9]
                if dst_ip != socket.inet_aton(self.target_host):
                    continue

                self.track_ip_state(src_ip_str, 'tcp')

                tcp_start = ip_start + (iph[0] & 0x0F) * 4
                tcp_header = packet[tcp_start:tcp_start + 20]
                if len(tcp_header) < 20:
                    continue

                tcph = struct.unpack('!HHLLBBHHH', tcp_header)
                src_port, dst_port = tcph[0], tcph[1]
                seq_num, ack_num = tcph[2], tcph[3]
                flags = tcph[5]

                option_data = packet[tcp_start + 20:ip_start + iph[2] - 14]
                tcp_options = self.parse_tcp_options(option_data)

                # Simulated TCP timestamp
                ts_val = int((time.time() - self.ts_start) * 1000) & 0xFFFFFFFF
                ts_ecr = tcp_options.get('ts_val', 0)
                tcp_options['ts_val'] = ts_val
                tcp_options['ts_ecr'] = ts_ecr

                if flags == 0x02:
                    logger.info(f"📥 SYN probe from {socket.inet_ntoa(src_ip)}:{src_port}")
                    reply_seq = 0
                    reply_ack = seq_num + 1
                    time.sleep(random.uniform(0.02, 0.1))
                    response = self.build_packet(
                        src_ip=dst_ip, dst_ip=src_ip,
                        src_port=dst_port, dst_port=src_port,
                        seq=reply_seq, ack=reply_ack,
                        flags=port_flag, vlan=vlan_tag,
                        tcp_options=tcp_options
                    )
                elif flags == 0x10:
                    logger.info(f"📥 ACK probe from {socket.inet_ntoa(src_ip)}:{src_port}")
                    reply_seq = ack_num
                    reply_ack = 0
                    time.sleep(random.uniform(0.02, 0.08))
                    response = self.build_packet(
                        src_ip=dst_ip, dst_ip=src_ip,
                        src_port=dst_port, dst_port=src_port,
                        seq=reply_seq, ack=reply_ack,
                        flags=0x04, vlan=vlan_tag,
                        tcp_options=tcp_options
                    )
                else:
                    continue

                self.conn.sock.send(response)
                logger.info(f"📤 Deceptive TCP response sent to {socket.inet_ntoa(src_ip)}:{src_port}")
        except KeyboardInterrupt:
            logger.info("🛑 Port deception stopped by user.")
        except Exception as e:
            logger.error(f"❌ Deception error: {e}")
        finally:
            self.export_state_log()

    def build_packet(self, src_ip, dst_ip, src_port, dst_port, seq, ack, flags, vlan=None, tcp_options=None):
        ip_ver_ihl = (4 << 4) + 5
        ip_tos = 0
        ip_tot_len = 40
        ip_id = self.generate_ip_id()
        ip_frag_off = 0
        ip_ttl = self.ttl
        ip_proto = socket.IPPROTO_TCP
        ip_chk = 0
        ip_header = struct.pack('!BBHHHBBH4s4s',
                                ip_ver_ihl, ip_tos, ip_tot_len,
                                ip_id, ip_frag_off,
                                ip_ttl, ip_proto,
                                ip_chk, src_ip, dst_ip)
        ip_chk = self._checksum(ip_header)
        ip_header = ip_header[:10] + struct.pack('!H', ip_chk) + ip_header[12:]

        options = b''
        if self.ws > 0:
            options += struct.pack('!BBB', 3, 3, self.ws)
        if tcp_options:
            if 'mss' in tcp_options:
                options = struct.pack('!BBH', 2, 4, tcp_options['mss']) + options
            if 'ts_val' in tcp_options and 'ts_ecr' in tcp_options:
                options += struct.pack('!BBII', 8, 10, tcp_options['ts_val'], tcp_options['ts_ecr'])
        while len(options) % 4:
            options += struct.pack('!B', 0)

        offset = 5 + len(options) // 4
        offset_res_flags = (offset << 12) | flags
        scaled_win = self.win << self.ws

        tcp_header = struct.pack('!HHLLHHHH',
                                 src_port, dst_port, seq, ack,
                                 offset_res_flags, scaled_win,
                                 0, 0)

        pseudo_hdr = struct.pack('!4s4sBBH', src_ip, dst_ip, 0, ip_proto, len(tcp_header + options))
        tcp_chk = self._checksum(pseudo_hdr + tcp_header + options)
        tcp_header = tcp_header[:16] + struct.pack('!H', tcp_chk) + tcp_header[18:] + options

        eth_src_mac = bytes.fromhex(settings.MAC.replace(':', ''))
        eth_dst_mac = b'\x11\x22\x33\x44\x55\x66'

        if vlan is not None:
            eth_header = struct.pack('!6s6sHHH', eth_dst_mac, eth_src_mac, 0x8100, vlan, 0x0800)
        else:
            eth_header = struct.pack('!6s6sH', eth_dst_mac, eth_src_mac, 0x0800)

        return eth_header + ip_header + tcp_header

    def generate_ip_id(self):
        if self.ip_id_mode == "increment":
            self.ip_id_counter = (self.ip_id_counter + 1) % 65536
            return self.ip_id_counter
        elif self.ip_id_mode == "random":
            return random.randint(0, 65535)
        else:
            return 0

    def parse_tcp_options(self, data: bytes):
        options = {}
        i = 0
        while i < len(data):
            kind = data[i]
            if kind == 0:
                break
            elif kind == 1:
                i += 1
                continue
            if i + 1 >= len(data):
                break
            length = data[i+1]
            if i + length > len(data):
                break
            value = data[i+2:i+length]
            if kind == 2 and len(value) >= 2:
                options['mss'] = struct.unpack('!H', value[:2])[0]
            elif kind == 3 and len(value) >= 1:
                options['ws'] = struct.unpack('!B', value[:1])[0]
            elif kind == 8 and len(value) >= 8:
                options['ts_val'], options['ts_ecr'] = struct.unpack('!II', value[:8])
            i += length
        return options

    def track_ip_state(self, ip: str, proto: str):
        if ip not in self.ip_state:
            self.ip_state[ip] = {
                'first_seen': time.time(),
                'tcp_count': 0,
                'icmp_count': 0,
                'udp_count': 0
            }
        key = f"{proto}_count"
        if key in self.ip_state[ip]:
            self.ip_state[ip][key] += 1

    def export_state_log(self):
        try:
            state_path = os.path.join(self.os_record_path, "state_log.json")
            with open(state_path, "w") as f:
                json.dump(self.ip_state, f, indent=2)
            logger.info(f"🧾 Exported per-IP state log to {state_path}")
        except Exception as e:
            logger.error(f"❌ Failed to export state log: {e}")

    def _checksum(self, data: bytes) -> int:
        if len(data) % 2:
            data += b'\x00'
        s = sum((data[i] << 8) + data[i + 1] for i in range(0, len(data), 2))
        while s >> 16:
            s = (s & 0xFFFF) + (s >> 16)
        return ~s & 0xFFFF
