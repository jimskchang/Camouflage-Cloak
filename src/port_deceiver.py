# src/port_deceiver.py
import logging
import socket
import struct
import random
import src.settings as settings
from src.tcp import TcpConnect, getTCPChecksum, getIPChecksum
from src.Packet import Packet

# Protocol and Flag Constants
ETHERNET_PROTOCOL_IP = 0x0800
PROTOCOL_TCP = 6
TCP_FLAG_SYN = 0x02
TCP_FLAG_ACK = 0x10
TCP_FLAG_RST = 0x04
TCP_FLAG_SYN_ACK = 0x12
TCP_FLAG_RST_ACK = 0x14

def get_random_ttl(os_template: str) -> int:
    return settings.OS_TEMPLATES.get(os_template, {}).get("TTL", random.choice([64, 128, 255]))

def get_random_tcp_window(os_template: str) -> int:
    return settings.OS_TEMPLATES.get(os_template, {}).get("WINDOW", random.choice([8192, 16384, 65535]))

class PortDeceiver:
    def __init__(self, host: str, os_template: str = "generic"):
        self.host = host
        self.os_template = os_template
        self.conn = TcpConnect(host, settings.NIC_PROBE)
        logging.info(f"✅ Port deception initialized for host {self.host} on NIC_PROBE: {settings.NIC_PROBE}")

    def send_packet(self, recv_flags: list, reply_flags: list):
        while True:
            try:
                packet, _ = self.conn.sock.recvfrom(65565)
                if struct.unpack('!H', packet[12:14])[0] != ETHERNET_PROTOCOL_IP:
                    continue

                ip_header = packet[settings.ETH_HEADER_LEN: settings.ETH_HEADER_LEN + settings.IP_HEADER_LEN]
                fields = struct.unpack('!BBHHHBBH4s4s', ip_header)
                src_IP, dest_IP, proto = fields[8], fields[9], fields[6]

                if dest_IP != socket.inet_aton(self.conn.dip) or proto != PROTOCOL_TCP:
                    continue

                tcp_start = settings.ETH_HEADER_LEN + settings.IP_HEADER_LEN
                tcp_header = packet[tcp_start: tcp_start + settings.TCP_HEADER_LEN]
                src_port, dest_port, seq, ack_num, offset, flags, *_ = struct.unpack('!HHLLBBHHH', tcp_header)

                if flags not in recv_flags:
                    continue

                for i, recv_flag in enumerate(recv_flags):
                    if flags == recv_flag:
                        reply_flags_val = reply_flags[i]
                        if reply_flags_val == 0:
                            continue

                        reply_tcp = self.conn.build_tcp_header_from_reply(
                            5, ack_num, seq + 1, dest_port, src_port,
                            dest_IP, src_IP, reply_flags_val
                        )
                        spoofed_packet = packet[:settings.ETH_HEADER_LEN + settings.IP_HEADER_LEN] + reply_tcp
                        self.conn.sock.send(spoofed_packet)
                        logging.info(f"📤 Sent spoofed response with flag {reply_flags_val}")
                return True
            except Exception as e:
                logging.error(f"❌ Error in send_packet: {e}")

    def deceive_ps_hs(self, port_status: str):
        reply_flag = TCP_FLAG_SYN_ACK if port_status == 'open' else TCP_FLAG_RST_ACK
        logging.info(f"🛡️ Simulating {'open' if port_status == 'open' else 'closed'} ports using flag {reply_flag}")

        while True:
            try:
                packet, _ = self.conn.sock.recvfrom(65565)
                if struct.unpack('!H', packet[12:14])[0] != ETHERNET_PROTOCOL_IP:
                    continue

                ip_header = packet[settings.ETH_HEADER_LEN:settings.ETH_HEADER_LEN + settings.IP_HEADER_LEN]
                fields = struct.unpack('!BBHHHBBH4s4s', ip_header)
                src_IP, dest_IP, proto = fields[8], fields[9], fields[6]

                if dest_IP != socket.inet_aton(self.conn.dip) or proto != PROTOCOL_TCP:
                    continue

                tcp_start = settings.ETH_HEADER_LEN + settings.IP_HEADER_LEN
                tcp_header = packet[tcp_start: tcp_start + settings.TCP_HEADER_LEN]
                src_port, dest_port, seq, ack_num, _, flags, *_ = struct.unpack('!HHLLBBHHH', tcp_header)

                if flags != TCP_FLAG_SYN:
                    continue

                ttl = get_random_ttl(self.os_template)
                window = get_random_tcp_window(self.os_template)
                reply_tcp = self.conn.build_tcp_header_from_reply(
                    5, ack_num, seq + 1, dest_port, src_port, src_IP, dest_IP, reply_flag
                )
                spoofed_packet = packet[:settings.ETH_HEADER_LEN + settings.IP_HEADER_LEN] + reply_tcp
                self.conn.sock.send(spoofed_packet)
                logging.info(f"📤 Deceptive SYN-ACK/RST sent to {socket.inet_ntoa(src_IP)}")

            except Exception as e:
                logging.error(f"❌ Error in deceive_ps_hs: {e}")
