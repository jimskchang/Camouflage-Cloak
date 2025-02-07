import logging
import socket
import struct
import os
import sys

# Ensure the `src` directory is in the Python module path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# Import settings and handle failures
try:
    import settings
except ImportError:
    logging.warning("Failed to import settings.py. Ensure it exists in the correct directory.")
    settings = None

# Import TcpConnect and checksum functions
from tcp import TcpConnect, get_ip_checksum, get_tcp_checksum

class PortDeceiver:
    def __init__(self, host):
        self.host = host
        self.conn = TcpConnect(host)

    def send_packet(self, recv_flags, reply_flags):
        """Processes received packets and sends responses based on scan type."""
        while True:
            packet, _ = self.conn.sock.recvfrom(65565)
            eth_header = packet[: settings.ETH_HEADER_LEN]
            eth = struct.unpack('!6s6sH', eth_header)
            eth_protocol = socket.ntohs(eth[2])

            if eth_protocol != 8:  # Ignore non-IP packets
                continue

            # Build Ethernet header
            eth_dMAC, eth_sMAC = eth[0], eth[1]
            reply_eth_dMAC, reply_eth_sMAC = eth_sMAC, eth_dMAC
            reply_eth_header = struct.pack('!6s6sH', reply_eth_dMAC, reply_eth_sMAC, eth[2])

            # Extract IP header
            ip_header = packet[settings.ETH_HEADER_LEN: settings.ETH_HEADER_LEN + settings.IP_HEADER_LEN]
            IHL_VERSION, TYPE_OF_SERVICE, total_len, pktID, FRAGMENT_STATUS, TIME_TO_LIVE, PROTOCOL, check_sum_of_hdr, \
                src_IP, dest_IP = struct.unpack('!BBHHHBBH4s4s', ip_header)

            if dest_IP != socket.inet_aton(self.conn.dip):
                continue  # Ignore packets not destined for this host

            if PROTOCOL != 6:  # Ignore non-TCP packets
                continue

            # Build response IP header
            pktID = 456  # Arbitrary packet ID
            reply_src_IP, reply_dest_IP = dest_IP, src_IP
            check_sum_of_hdr = 0
            reply_ttl = TIME_TO_LIVE + 1
            total_len = 40  # Header size only
            reply_ip_header = struct.pack('!BBHHHBBH4s4s', IHL_VERSION, TYPE_OF_SERVICE, total_len, pktID,
                                          FRAGMENT_STATUS, reply_ttl, PROTOCOL, check_sum_of_hdr,
                                          reply_src_IP, reply_dest_IP)
            check_sum_of_hdr = get_ip_checksum(reply_ip_header)
            reply_ip_header = struct.pack('!BBHHHBBH4s4s', IHL_VERSION, TYPE_OF_SERVICE, total_len, pktID,
                                          FRAGMENT_STATUS, reply_ttl, PROTOCOL, check_sum_of_hdr,
                                          reply_src_IP, reply_dest_IP)

            # Extract TCP header
            tcp_header = packet[settings.ETH_HEADER_LEN + settings.IP_HEADER_LEN:
                                settings.ETH_HEADER_LEN + settings.IP_HEADER_LEN + settings.TCP_HEADER_LEN]
            src_port, dest_port, seq, ack_num, offset, flags, window, checksum, urgent_ptr = struct.unpack('!HHLLBBHHH', tcp_header)

            if flags in recv_flags:
                logging.info(f"Received flag: {flags}")
            else:
                continue

            reply_seq = ack_num
            reply_ack_num = seq + 1
            reply_src_port = dest_port
            reply_dest_port = src_port

            for i, recv_flag in enumerate(recv_flags):
                if flags == recv_flag:
                    if reply_flags[i] == 0:
                        continue
                    reply_tcp_header = self.conn.build_tcp_header_from_reply(
                        5, reply_seq, reply_ack_num, reply_src_port, reply_dest_port, reply_src_IP, reply_dest_IP, reply_flags[i]
                    )
                    response_packet = reply_eth_header + reply_ip_header + reply_tcp_header
                    self.conn.sock.send(response_packet)
                    logging.info(f"Sent response with flag: {reply_flags[i]}")

            return True  # Successfully processed one packet
