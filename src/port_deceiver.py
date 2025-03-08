import logging
import socket
import struct
import random
import threading
import src.settings as settings
from src.tcp import TcpConnect, getIPChecksum, getTCPChecksum

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


def get_random_ttl():
    return random.choice(TTL_VALUES)


def get_random_tcp_window():
    return random.choice(TCP_WINDOW_SIZES)


class PortDeceiver:
    def __init__(self, host):
        self.host = host
        self.conn = TcpConnect(host)

    def send_packet(self, recv_flags, reply_flags):
        while True:
            try:
                packet, _ = self.conn.sock.recvfrom(65565)
                eth_header = packet[:settings.ETH_HEADER_LEN]
                eth = struct.unpack('!6s6sH', eth_header)
                eth_protocol = socket.ntohs(eth[2])

                if eth_protocol != ETHERNET_PROTOCOL_IP:
                    continue

                ip_header = packet[settings.ETH_HEADER_LEN: settings.ETH_HEADER_LEN + settings.IP_HEADER_LEN]
                IHL_VERSION, TYPE_OF_SERVICE, total_len, pktID, FRAGMENT_STATUS, TIME_TO_LIVE, PROTOCOL, check_sum_of_hdr, \
                    src_IP, dest_IP = struct.unpack('!BBHHHBBH4s4s', ip_header)

                if dest_IP != socket.inet_aton(self.conn.dip) or PROTOCOL != PROTOCOL_TCP:
                    continue

                tcp_header = packet[settings.ETH_HEADER_LEN + settings.IP_HEADER_LEN:
                                    settings.ETH_HEADER_LEN + settings.IP_HEADER_LEN + settings.TCP_HEADER_LEN]
                src_port, dest_port, seq, ack_num, offset, flags, window, checksum, urgent_ptr = struct.unpack(
                    '!HHLLBBHHH', tcp_header)

                if flags not in recv_flags:
                    continue

                logging.info(f"Received TCP packet from {socket.inet_ntoa(src_IP)} to {socket.inet_ntoa(dest_IP)} with flags {flags}")

                reply_seq = ack_num
                reply_ack_num = seq + 1
                reply_src_port = dest_port
                reply_dest_port = src_port

                for i in range(len(recv_flags)):
                    if flags == recv_flags[i] and reply_flags[i] != 0:
                        reply_tcp_header = self.conn.build_tcp_header_from_reply(5, reply_seq, reply_ack_num,
                                                                                 reply_src_port, reply_dest_port,
                                                                                 dest_IP, src_IP, reply_flags[i])
                        packet = eth_header + ip_header + reply_tcp_header
                        self.conn.sock.send(packet)
                        logging.info(f"Sent deceptive reply with flag {reply_flags[i]}")
                return True
            except Exception as e:
                logging.error(f"Error processing packet: {e}")
                continue

    def deceive_ps_hs(self, port_status):
        if port_status == 'open':
            port_flag = TCP_FLAG_SYN_ACK
            logging.info("Deceiving port scan: Simulating open port")
        elif port_status == 'close':
            port_flag = TCP_FLAG_RST_ACK
            logging.info("Deceiving port scan: Simulating closed port")
        else:
            logging.warning("Invalid port status. Use 'open' or 'close'.")
            return

        while True:
            try:
                packet, _ = self.conn.sock.recvfrom(65565)
                eth_header = packet[:settings.ETH_HEADER_LEN]
                eth = struct.unpack('!6s6sH', eth_header)
                eth_protocol = socket.ntohs(eth[2])

                if eth_protocol != ETHERNET_PROTOCOL_IP:
                    continue

                ip_header = packet[settings.ETH_HEADER_LEN: settings.ETH_HEADER_LEN + settings.IP_HEADER_LEN]
                IHL_VERSION, TYPE_OF_SERVICE, total_len, pktID, FRAGMENT_STATUS, TIME_TO_LIVE, PROTOCOL, check_sum_of_hdr, \
                    src_IP, dest_IP = struct.unpack('!BBHHHBBH4s4s', ip_header)

                if dest_IP != socket.inet_aton(self.conn.dip):
                    continue

                reply_ttl = get_random_ttl()
                tcp_header = packet[settings.ETH_HEADER_LEN + settings.IP_HEADER_LEN:
                                    settings.ETH_HEADER_LEN + settings.IP_HEADER_LEN + settings.TCP_HEADER_LEN]
                src_port, dest_port, seq, ack_num, offset, flags, window, checksum, urgent_ptr = struct.unpack(
                    '!HHLLBBHHH', tcp_header)

                reply_seq = ack_num
                reply_ack_num = seq + 1
                reply_src_port = dest_port
                reply_dest_port = src_port

                if flags == TCP_FLAG_SYN:
                    logging.info("Received SYN, responding with deception")
                    reply_tcp_header = self.conn.build_tcp_header_from_reply(5, reply_seq, reply_ack_num,
                                                                             reply_src_port, reply_dest_port,
                                                                             reply_src_IP, reply_dest_IP, port_flag)
                elif flags == TCP_FLAG_ACK:
                    logging.info("Received ACK, responding with RST")
                    reply_tcp_header = self.conn.build_tcp_header_from_reply(5, reply_seq, reply_ack_num,
                                                                             reply_src_port, reply_dest_port,
                                                                             reply_src_IP, reply_dest_IP, TCP_FLAG_RST)
                else:
                    continue

                packet = eth_header + ip_header + reply_tcp_header
                self.conn.sock.send(packet)
            except Exception as e:
                logging.error(f"Error processing packet: {e}")
                continue
