import logging
import socket
import struct
import random
import src.settings as settings
from src.tcp import TcpConnect, getTCPChecksum
from src.Packet import Packet  # Ensure Packet handles IP checksum calculation

# Constants for readability
ETHERNET_PROTOCOL_IP = 8
PROTOCOL_TCP = 6
PROTOCOL_ICMP = 1

# TCP Flags
TCP_FLAG_SYN = 0x02
TCP_FLAG_ACK = 0x10
TCP_FLAG_RST = 0x04
TCP_FLAG_SYN_ACK = 0x12
TCP_FLAG_RST_ACK = 0x14

# Fake Packet Defaults
FAKE_PKT_ID = 456
TTL_VALUES = [64, 128, 255]  # Linux, Windows, Mac/FreeBSD
TCP_WINDOW_SIZES = [8192, 16384, 32768]  # Common TCP window sizes

# Configure logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

def get_random_ttl() -> int:
    """Returns a random TTL value based on common OS defaults."""
    return random.choice(TTL_VALUES)

def get_random_tcp_window() -> int:
    """Returns a random TCP window size to evade fingerprinting."""
    return random.choice(TCP_WINDOW_SIZES)

class PortDeceiver:
    def __init__(self, host: str):
        """
        Initializes the PortDeceiver for misleading port scans.
        """
        self.host = host
        self.conn = TcpConnect(host)

    def send_packet(self, recv_flags: list, reply_flags: list) -> bool:
        """
        Listens for incoming TCP packets and sends deceptive responses.
        """
        while True:
            try:
                packet, _ = self.conn.sock.recvfrom(65565)
                eth_protocol = struct.unpack('!H', packet[12:14])[0]
                
                if eth_protocol != ETHERNET_PROTOCOL_IP:
                    continue
                
                ip_header = packet[settings.ETH_HEADER_LEN: settings.ETH_HEADER_LEN + settings.IP_HEADER_LEN]
                fields = struct.unpack('!BBHHHBBH4s4s', ip_header)
                dest_IP, src_IP, PROTOCOL = fields[8], fields[9], fields[6]
                
                if dest_IP != socket.inet_aton(self.conn.dip) or PROTOCOL != PROTOCOL_TCP:
                    continue
                
                tcp_header_start = settings.ETH_HEADER_LEN + settings.IP_HEADER_LEN
                tcp_header = packet[tcp_header_start: tcp_header_start + settings.TCP_HEADER_LEN]
                src_port, dest_port, seq, ack_num, _, flags, *_ = struct.unpack('!HHLLBBHHH', tcp_header)
                
                if flags not in recv_flags:
                    continue
                
                logging.info(f"Received TCP packet from {socket.inet_ntoa(src_IP)} to {socket.inet_ntoa(dest_IP)} with flags {flags}")
                
                reply_seq, reply_ack_num = ack_num, seq + 1
                reply_src_port, reply_dest_port = dest_port, src_port
                
                for i, recv_flag in enumerate(recv_flags):
                    if flags == recv_flag and reply_flags[i] != 0:
                        reply_tcp_header = self.conn.build_tcp_header_from_reply(
                            5, reply_seq, reply_ack_num, reply_src_port, reply_dest_port,
                            dest_IP, src_IP, reply_flags[i]
                        )
                        packet = packet[:settings.ETH_HEADER_LEN + settings.IP_HEADER_LEN] + reply_tcp_header
                        self.conn.sock.send(packet)
                        logging.info(f"Sent deceptive reply with flag {reply_flags[i]}")
                return True
            except Exception as e:
                logging.error(f"Error processing packet: {e}")
                continue

    def deceive_ps_hs(self, port_status: str) -> None:
        """
        Deceives port scans by making ports appear open or closed.
        """
        port_flag = TCP_FLAG_SYN_ACK if port_status == 'open' else TCP_FLAG_RST_ACK
        logging.info(f"Deceiving port scan: Simulating {'open' if port_status == 'open' else 'closed'} port")
        
        while True:
            try:
                packet, _ = self.conn.sock.recvfrom(65565)
                eth_protocol = struct.unpack('!H', packet[12:14])[0]
                
                if eth_protocol != ETHERNET_PROTOCOL_IP:
                    continue
                
                ip_header = packet[settings.ETH_HEADER_LEN: settings.ETH_HEADER_LEN + settings.IP_HEADER_LEN]
                fields = struct.unpack('!BBHHHBBH4s4s', ip_header)
                dest_IP, src_IP, PROTOCOL = fields[8], fields[9], fields[6]
                
                if dest_IP != socket.inet_aton(self.conn.dip):
                    continue
                
                reply_ttl = get_random_ttl()
                tcp_header_start = settings.ETH_HEADER_LEN + settings.IP_HEADER_LEN
                tcp_header = packet[tcp_header_start: tcp_header_start + settings.TCP_HEADER_LEN]
                src_port, dest_port, seq, ack_num, _, flags, *_ = struct.unpack('!HHLLBBHHH', tcp_header)
                
                reply_seq, reply_ack_num = ack_num, seq + 1
                reply_src_port, reply_dest_port = dest_port, src_port
                
                if flags == TCP_FLAG_SYN:
                    logging.info("Received SYN, responding with deception")
                    reply_tcp_header = self.conn.build_tcp_header_from_reply(
                        5, reply_seq, reply_ack_num, reply_src_port, reply_dest_port,
                        src_IP, dest_IP, port_flag
                    )
                elif flags == TCP_FLAG_ACK:
                    logging.info("Received ACK, responding with RST")
                    reply_tcp_header = self.conn.build_tcp_header_from_reply(
                        5, reply_seq, reply_ack_num, reply_src_port, reply_dest_port,
                        src_IP, dest_IP, TCP_FLAG_RST
                    )
                else:
                    continue
                
                packet = packet[:settings.ETH_HEADER_LEN + settings.IP_HEADER_LEN] + reply_tcp_header
                self.conn.sock.send(packet)
            except Exception as e:
                logging.error(f"Error processing packet: {e}")
                continue

