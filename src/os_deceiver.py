from datetime import datetime, timedelta
import logging
import random
import socket
import struct
from typing import List, Any

import os
import sys

# Ensure the `src` directory is in the Python module path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import settings  # Import settings after modifying the path
from Packet import Packet
from tcp import TcpConnect

count = 0


class OsDeceiver:
    white_list = []

    def __init__(self, host, os):
        self.host = host
        self.os = os
        self.conn = TcpConnect(host)
        self.knocking_history = {}
        self.white_list = {}
        # self.port_seq = [random.randint(0, 65535) for _ in range(3)]
        self.port_seq = [4441, 5551, 6661]

    def os_record(self):
        arp_pkt_dict = {}
        ip_pair_seq = []
        arp_key_seq = []

        udp_pkt_dict = {}

        icmp_pkt_dict = {}
        id_pair_seq = []
        icmp_key_seq = []

        pkt_dict = {}
        port_pair_seq = []
        key_seq = []  # prevent IndexError because dict.keys() would ignore same keys

        count = 1
        while True:
            packet, _ = self.conn.sock.recvfrom(65565)
            eth_header = packet[: settings.ETH_HEADER_LEN]
            eth = struct.unpack('!6s6sH', eth_header)
            eth_protocol = socket.ntohs(eth[2])

            # ip=8
            if eth_protocol == 8:
                ip_header = packet[settings.ETH_HEADER_LEN: settings.ETH_HEADER_LEN + settings.IP_HEADER_LEN]
                _, _, _, _, _, _, PROTOCOL, _, src_IP, dest_IP = struct.unpack('!BBHHHBBH4s4s', ip_header)

                # tcp=6
                if PROTOCOL == 6:
                    tcp_header = packet[settings.ETH_HEADER_LEN + settings.IP_HEADER_LEN: settings.ETH_HEADER_LEN
                                        + settings.IP_HEADER_LEN + settings.TCP_HEADER_LEN]
                    src_port, dest_port, seq, ack_num, offset, flags, window, checksum, urgent_ptr = struct.unpack(
                        '!HHLLBBHHH', tcp_header)

                    # store pkt as key
                    if dest_IP == socket.inet_aton(self.host):
                        key, packet_val = gen_tcp_key(packet)
                        if packet_val['flags'] == 4:
                            continue
                        port_pair_seq.append((src_port, dest_port))
                        key_seq.append(key)
                        if key not in pkt_dict.keys():
                            pkt_dict[key] = None

                    # store response pkt as value
                    elif src_IP == socket.inet_aton(self.host) and (dest_port, src_port) in port_pair_seq:
                        pkt_index = port_pair_seq.index((dest_port, src_port))
                        key = key_seq[pkt_index]
                        if pkt_dict[key] is None:  # assume same packet format received would have same replied format
                            print('add %d reply' % count)
                            count += 1
                            pkt_dict[key] = packet

                    else:
                        continue

                    with open('tcp_record.txt', 'w') as f:
                        f.write(str(pkt_dict))

                # icmp=1
                elif PROTOCOL == 1:
                    icmp_header = packet[settings.ETH_HEADER_LEN + settings.IP_HEADER_LEN: settings.ETH_HEADER_LEN +
                                                                                               settings.IP_HEADER_LEN + settings.ICMP_HEADER_LEN]
                    icmp_type, code, checksum, ID, seq = struct.unpack('BbHHh', icmp_header)

                    # store pkt as key
                    if dest_IP == socket.inet_aton(self.host):
                        key, packet_val = gen_icmp_key(packet)
                        id_pair_seq.append(ID)
                        icmp_key_seq.append(key)
                        if key not in icmp_pkt_dict.keys():
                            icmp_pkt_dict[key] = None

                    # store response pkt as value
                    elif src_IP == socket.inet_aton(self.host):
                        if ID in id_pair_seq:
                            pkt_index = id_pair_seq.index(ID)
                            key = icmp_key_seq[pkt_index]
                            icmp_pkt_dict[key] = packet
                        else:
                            continue

                    with open('icmp_record.txt', 'w') as f:
                        f.write(str(icmp_pkt_dict))

                # udp=17
                elif PROTOCOL == 17:
                    if dest_IP == socket.inet_aton(self.host):
                        key, packet_val = gen_udp_key(packet)
                        if key not in udp_pkt_dict.keys():
                            udp_pkt_dict[key] = None
                    else:
                        continue

                    with open('udp_record.txt', 'w') as f:
                        f.write(str(udp_pkt_dict))

                else:
                    continue

            # arp=1544
            elif eth_protocol == 1544:
                arp_header = packet[settings.ETH_HEADER_LEN: settings.ETH_HEADER_LEN + settings.ARP_HEADER_LEN]
                hw_type, proto_type, hw_size, proto_size, opcode, sender_mac, sender_ip, recv_mac, recv_ip = \
                    struct.unpack('2s2s1s1s2s6s4s6s4s', arp_header)

                if recv_ip == socket.inet_aton(self.host):
                    key, packet_val = gen_arp_key(packet)
                    ip_pair_seq.append((sender_ip, recv_ip))
                    arp_key_seq.append(key)
                    if key not in arp_pkt_dict.keys():
                        arp_pkt_dict[key] = None

                elif sender_ip == socket.inet_aton(self.host) and (recv_ip, sender_ip) in ip_pair_seq:
                    pkt_index = ip_pair_seq.index((recv_ip, sender_ip))
                    key = arp_key_seq[pkt_index]
                    arp_pkt_dict[key] = packet

                else:
                    continue

                with open('arp_record.txt', 'w') as f:
                    f.write(str(arp_pkt_dict))

            else:
                continue
