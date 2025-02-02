import logging
import socket
import struct
import os

import src.settings as settings
from src.tcp import TcpConnect, getIPChecksum, getTCPChecksum


class PortDeceiver:
    def __init__(self, host):
        self.host = host
        self.conn = TcpConnect(host)

    def send_packet(self, recv_flags, reply_flags, output_path=None):
        """Handles packet replies for deceptive port responses"""
        if not output_path:
            output_path = os.path.join(settings.TS_OS_OUTPUT_DIR, "pkt_record.txt")

        logging.info(f"Recording deceptive packets in {output_path}")

        while True:
            packet, _ = self.conn.sock.recvfrom(65565)
            eth_header = packet[: settings.ETH_HEADER_LEN]
            eth = struct.unpack('!6s6sH', eth_header)
            eth_protocol = socket.ntohs(eth[2])

            if eth_protocol != 8:
                continue

            # Extract IP header
            ip_header = packet[settings.ETH_HEADER_LEN: settings.ETH_HEADER_LEN + settings.IP_HEADER_LEN]
            (IHL_VERSION, TYPE_OF_SERVICE, total_len, pktID, FRAGMENT_STATUS, TIME_TO_LIVE, 
             PROTOCOL, check_sum_of_hdr, src_IP, dest_IP) = struct.unpack('!BBHHHBBH4s4s', ip_header)

            if dest_IP != socket.inet_aton(settings.TARGET_HOST):
                continue

            # TCP Processing
            if PROTOCOL == 6:
                tcp_header = packet[settings.ETH_HEADER_LEN + settings.IP_HEADER_LEN:
                                    settings.ETH_HEADER_LEN + settings.IP_HEADER_LEN + settings.TCP_HEADER_LEN]
                (src_port, dest_port, seq, ack_num, offset, flags, window, checksum, urgent_ptr) = struct.unpack(
                    '!HHLLBBHHH', tcp_header)

                if flags in recv_flags:
                    logging.info(f"Received TCP flag={flags}, preparing response.")
                else:
                    continue

                reply_seq = ack_num
                reply_ack_num = seq + 1
                reply_src_port = dest_port
                reply_dest_port = src_port

                num_recv = len(recv_flags)
                for i in range(num_recv):
                    if flags == recv_flags[i]:
                        if reply_flags[i] == 0:
                            continue
                        reply_tcp_header = self.conn.build_tcp_header_from_reply(
                            5, reply_seq, reply_ack_num, reply_src_port, reply_dest_port,
                            dest_IP, src_IP, reply_flags[i]
                        )
                        packet = self.build_eth_ip_header(dest_IP, src_IP) + reply_tcp_header
                        self.conn.sock.send(packet)
                        logging.info(f"Sent TCP response with flag={reply_flags[i]}")

            # Save to file
            with open(output_path, 'a') as f:
                f.write(str(packet) + '\n')

    def deceive_ps_hs(self, port_status, output_path=None):
        """Deceives port scanning techniques"""
        if not output_path:
            output_path = os.path.join(settings.TS_OS_OUTPUT_DIR, "deception_log.txt")

        logging.info(f"Deceiving port scan as {port_status}, logging responses to {output_path}")

        if port_status == 'open':
            port_flag = 18  # SYN-ACK
        elif port_status == 'close':
            port_flag = 20  # RST-ACK
        else:
            logging.error("Invalid port status. Use 'open' or 'close'.")
            return

        while True:
            packet, _ = self.conn.sock.recvfrom(65565)
            eth_header = packet[: settings.ETH_HEADER_LEN]
            eth = struct.unpack('!6s6sH', eth_header)
            eth_protocol = socket.ntohs(eth[2])

            if eth_protocol != 8:
                continue

            # Extract IP header
            ip_header = packet[settings.ETH_HEADER_LEN: settings.ETH_HEADER_LEN + settings.IP_HEADER_LEN]
            (IHL_VERSION, TYPE_OF_SERVICE, total_len, pktID, FRAGMENT_STATUS, TIME_TO_LIVE, 
             PROTOCOL, check_sum_of_hdr, src_IP, dest_IP) = struct.unpack('!BBHHHBBH4s4s', ip_header)

            if dest_IP != socket.inet_aton(settings.TARGET_HOST):
                continue

            # TCP Processing
            if PROTOCOL == 6:
                tcp_header = packet[settings.ETH_HEADER_LEN + settings.IP_HEADER_LEN:
                                    settings.ETH_HEADER_LEN + settings.IP_HEADER_LEN + settings.TCP_HEADER_LEN]
                (src_port, dest_port, seq, ack_num, offset, flags, window, checksum, urgent_ptr) = struct.unpack(
                    '!HHLLBBHHH', tcp_header)

                reply_seq = ack_num
                reply_ack_num = seq + 1
                reply_src_port = dest_port
                reply_dest_port = src_port

                if flags == 2:  # SYN received
                    logging.info("Received SYN, sending deceptive response.")
                    reply_tcp_header = self.conn.build_tcp_header_from_reply(
                        5, reply_seq, reply_ack_num, reply_src_port, reply_dest_port,
                        dest_IP, src_IP, port_flag
                    )
                elif flags == 16:  # ACK received
                    logging.info("Received ACK, sending RST.")
                    reply_tcp_header = self.conn.build_tcp_header_from_reply(
                        5, reply_seq, reply_ack_num, reply_src_port, reply_dest_port,
                        dest_IP, src_IP, 4  # RST
                    )
                else:
                    continue

                packet = self.build_eth_ip_header(dest_IP, src_IP) + reply_tcp_header
                self.conn.sock.send(packet)

            # Save to log
            with open(output_path, 'a') as f:
                f.write(str(packet) + '\n')

    def build_eth_ip_header(self, src_ip, dest_ip):
        """Builds Ethernet and IP headers for deceptive responses"""
        eth_header = struct.pack('!6s6sH', settings.CLOAK_MAC, settings.TARGET_MAC, 0x0800)  # IP Protocol
        ip_header = struct.pack('!BBHHHBBH4s4s', 69, 0, 40, 456, 0, 64, 6, 0, src_ip, dest_ip)  # Default IP Header
        check_sum_of_hdr = getIPChecksum(ip_header)
        ip_header = struct.pack('!BBHHHBBH4s4s', 69, 0, 40, 456, 0, 64, 6, check_sum_of_hdr, src_ip, dest_ip)
        return eth_header + ip_header
