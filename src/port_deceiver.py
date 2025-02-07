import logging
import socket
import struct
import os
import sys

# Ensure the `src` directory is in the Python module path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import settings  # Import settings after modifying the path
from tcp import TcpConnect, getIPChecksum, getTCPChecksum

class PortDeceiver:
    def __init__(self, host):
        self.host = host
        self.conn = TcpConnect(host)

    def send_packet(self, recv_flags, reply_flags):
        while True:
            packet, _ = self.conn.sock.recvfrom(65565)
            eth_header = packet[: settings.ETH_HEADER_LEN]
            eth = struct.unpack('!6s6sH', eth_header)
            eth_protocol = socket.ntohs(eth[2])

            if eth_protocol != 8:
                continue

            # build eth_header
            eth_dMAC = eth[0]
            eth_sMAC = eth[1]
            reply_eth_dMAC = eth_sMAC
            reply_eth_sMAC = eth_dMAC
            reply_eth_header = struct.pack('!6s6sH', reply_eth_dMAC, reply_eth_sMAC, eth[2])

            ip_header = packet[settings.ETH_HEADER_LEN: settings.ETH_HEADER_LEN + settings.IP_HEADER_LEN]
            IHL_VERSION, TYPE_OF_SERVICE, total_len, pktID, FRAGMENT_STATUS, TIME_TO_LIVE, PROTOCOL, check_sum_of_hdr, \
                src_IP, dest_IP = struct.unpack('!BBHHHBBH4s4s', ip_header)

            if dest_IP != socket.inet_aton(self.conn.dip):
                continue

            # tcp=0x06
            if PROTOCOL != 6:
                continue

            # build ip_header
            pktID = 456  # arbitrary number
            reply_src_IP = dest_IP
            reply_dest_IP = src_IP
            check_sum_of_hdr = 0
            reply_ttl = TIME_TO_LIVE + 1
            total_len = 40
            reply_ip_header = struct.pack('!BBHHHBBH4s4s', IHL_VERSION, TYPE_OF_SERVICE, total_len, pktID,
                                          FRAGMENT_STATUS, reply_ttl, PROTOCOL, check_sum_of_hdr,
                                          reply_src_IP, reply_dest_IP)
            check_sum_of_hdr = getIPChecksum(reply_ip_header)
            reply_ip_header = struct.pack('!BBHHHBBH4s4s', IHL_VERSION, TYPE_OF_SERVICE, total_len, pktID,
                                          FRAGMENT_STATUS, reply_ttl, PROTOCOL, check_sum_of_hdr,
                                          reply_src_IP, reply_dest_IP)

            tcp_header = packet[settings.ETH_HEADER_LEN + settings.IP_HEADER_LEN: settings.ETH_HEADER_LEN
                                                            + settings.IP_HEADER_LEN + settings.TCP_HEADER_LEN]
            src_port, dest_port, seq, ack_num, offset, flags, window, checksum, urgent_ptr = struct.unpack('!HHLLBBHHH',
                                                                                                           tcp_header)

            if flags in recv_flags:
                print('receive flag=' + str(flags))
                pass
            else:
                continue

            reply_seq = ack_num
            reply_ack_vum = seq + 1
            reply_src_port = dest_port
            reply_dest_port = src_port
            num_recv = len(recv_flags)

            for i in range(num_recv):
                if flags == recv_flags[i]:
                    if reply_flags[i] == 0:
                        continue
                    reply_tcp_header = self.conn.build_tcp_header_from_reply(5, reply_seq, reply_ack_vum,
                                                                             reply_src_port, reply_dest_port,
                                                                             reply_src_IP, reply_dest_IP,
                                                                             reply_flags[i])
                    packet = reply_eth_header + reply_ip_header + reply_tcp_header
                    self.conn.sock.send(packet)
                    print('reply flag=' + str(reply_flags[i]))

            return True
