"""
port_deceiver.py - Camouflage Cloak Project
Handles TCP port scan deception by responding to probes with OS-specific
network characteristics to mislead reconnaissance tools like Nmap.
"""

import logging
import socket
import struct
import random

import src.settings as settings
from src.tcp import TcpConnect

logger = logging.getLogger(__name__)

class PortDeceiver:
    def __init__(self, target_host: str, nic: str = None, os_name: str = None):
        """
        Initialize deception engine for port-based probes.
        :param target_host: The host IP we are protecting.
        :param nic: Network interface used to send deception responses.
        :param os_name: Name of the OS template to mimic (e.g. win10).
        """
        self.target_host = target_host
        self.nic = nic or settings.NIC_PROBE
        self.os_name = os_name

        # Load TTL and TCP window from settings
        tmpl = settings.OS_TEMPLATES.get(os_name, {})
        self.ttl = tmpl.get("ttl", 64)
        self.win = tmpl.get("tcp_window", 8192)

        try:
            self.conn = TcpConnect(self.target_host, nic=self.nic)
        except Exception as e:
            logger.error(f"❌ Failed to initialize TcpConnect on {self.nic}: {e}")
            raise

        logger.info(f"🛡️ PortDeceiver ready on {self.nic} for OS: {self.os_name or 'default'} "
                    f"(TTL={self.ttl}, TCP_WIN={self.win})")

    def deceive_ps_hs(self, port_status: str = 'open'):
        """
        Simulate port scan deception with SYN/ACK or RST/ACK based on desired port status.
        :param port_status: 'open' or 'close'
        """
        logger.info(f"🔄 Simulating ports as {'OPEN' if port_status == 'open' else 'CLOSED'}")
        port_flag = 0x12 if port_status == 'open' else 0x14  # SYN+ACK or RST+ACK

        try:
            while True:
                packet, _ = self.conn.sock.recvfrom(65565)
                if len(packet) < 34:
                    continue  # Too short for IP + TCP

                eth_type = struct.unpack('!H', packet[12:14])[0]
                if eth_type != 0x0800:
                    continue  # Not IP

                ip_header = packet[14:34]
                iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
                proto = iph[6]
                if proto != 6:
                    continue  # Not TCP

                src_ip, dst_ip = iph[8], iph[9]
                if dst_ip != socket.inet_aton(self.target_host):
                    continue  # Not addressed to us

                ip_total_length = iph[2]
                tcp_start = 14 + (iph[0] & 0x0F) * 4
                tcp_header = packet[tcp_start:tcp_start + 20]
                if len(tcp_header) < 20:
                    continue

                tcph = struct.unpack('!HHLLBBHHH', tcp_header)
                src_port, dst_port = tcph[0], tcph[1]
                seq_num, ack_num = tcph[2], tcph[3]
                flags = tcph[5]

                # Only react to SYN or ACK probes
                if flags == 0x02:  # SYN
                    logger.info(f"📥 SYN probe from {socket.inet_ntoa(src_ip)}:{src_port}")
                    reply_seq = 0
                    reply_ack = seq_num + 1
                    response = self.build_packet(
                        src_ip=dst_ip, dst_ip=src_ip,
                        src_port=dst_port, dst_port=src_port,
                        seq=reply_seq, ack=reply_ack,
                        flags=port_flag
                    )
                elif flags == 0x10:  # ACK
                    logger.info(f"📥 ACK probe from {socket.inet_ntoa(src_ip)}:{src_port}")
                    reply_seq = ack_num
                    reply_ack = 0
                    response = self.build_packet(
                        src_ip=dst_ip, dst_ip=src_ip,
                        src_port=dst_port, dst_port=src_port,
                        seq=reply_seq, ack=reply_ack,
                        flags=0x04  # RST only
                    )
                else:
                    continue  # Skip other flag types

                self.conn.sock.send(response)
                logger.info(f"📤 Deceptive TCP response sent to {socket.inet_ntoa(src_ip)}:{src_port}")
        except Exception as e:
            logger.error(f"❌ Deception error: {e}")

    def build_packet(self, src_ip, dst_ip, src_port, dst_port, seq, ack, flags):
        """
        Construct spoofed IP+TCP packet.
        """
        ip_ver_ihl = (4 << 4) + 5
        ip_tos = 0
        ip_tot_len = 40
        ip_id = random.randint(0, 65535)
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

        offset_res_flags = (5 << 12) | flags
        tcp_header = struct.pack('!HHLLHHHH',
                                 src_port, dst_port, seq, ack,
                                 offset_res_flags, self.win,
                                 0, 0)

        pseudo_hdr = struct.pack('!4s4sBBH', src_ip, dst_ip, 0, ip_proto, len(tcp_header))
        tcp_chk = self._checksum(pseudo_hdr + tcp_header)
        tcp_header = tcp_header[:16] + struct.pack('!H', tcp_chk) + tcp_header[18:]

        return ip_header + tcp_header

    def _checksum(self, data: bytes) -> int:
        """
        Generic checksum computation for IP/TCP headers.
        """
        if len(data) % 2:
            data += b'\x00'
        s = sum((data[i] << 8) + data[i + 1] for i in range(0, len(data), 2))
        while s >> 16:
            s = (s & 0xFFFF) + (s >> 16)
        return ~s & 0xFFFF
