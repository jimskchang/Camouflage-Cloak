from _datetime import datetime, timedelta
import logging
import random
import socket
import struct
from typing import List, Any

import src.settings as settings
from src.Packet import Packet
from src.tcp import TcpConnect


class OsDeceiver:
    white_list = []

    def __init__(self, host, os):
        self.host = host
        self.os = os
        self.conn = TcpConnect(host)
        self.knocking_history = {}
        self.white_list = {}
        self.port_seq = [4441, 5551, 6661]

    def os_record(self):
        arp_pkt_dict = {}
        ip_pair_seq = []
        arp_key_seq = []

        udp_pkt_dict = {}
        icmp_pkt_dict = {}  # Fix: Ensure dictionary is initialized
        id_pair_seq = []
        icmp_key_seq = []

        pkt_dict = {}
        port_pair_seq = []
        key_seq = []  # prevent IndexError since dict.keys() ignores duplicates

        count = 1
        while True:
            packet, _ = self.conn.sock.recvfrom(65565)
            eth_header = packet[: settings.ETH_HEADER_LEN]
            eth = struct.unpack('!6s6sH', eth_header)
            eth_protocol = socket.ntohs(eth[2])

            if eth_protocol == 8:  # IP packets
                ip_header = packet[settings.ETH_HEADER_LEN: settings.ETH_HEADER_LEN + settings.IP_HEADER_LEN]
                _, _, _, _, _, _, PROTOCOL, _, src_IP, dest_IP = struct.unpack('!BBHHHBBH4s4s', ip_header)
                
                logging.info(f"Received IP packet - Protocol: {PROTOCOL}, Source: {socket.inet_ntoa(src_IP)}, Dest: {socket.inet_ntoa(dest_IP)}")
                
                if PROTOCOL == 1:  # ICMP
                    icmp_header = packet[settings.ETH_HEADER_LEN + settings.IP_HEADER_LEN:
                                         settings.ETH_HEADER_LEN + settings.IP_HEADER_LEN + settings.ICMP_HEADER_LEN]
                    icmp_type, code, checksum, ID, seq = struct.unpack('BbHHh', icmp_header)

                    if socket.inet_ntoa(dest_IP) == self.host:  # Fix: Ensuring correct destination
                        key, packet_val = gen_icmp_key(packet)
                        id_pair_seq.append(ID)
                        icmp_key_seq.append(key)
                        if key not in icmp_pkt_dict.keys():
                            icmp_pkt_dict[key] = None

                    elif socket.inet_ntoa(src_IP) == self.host:  # ICMP Response handling
                        if ID in id_pair_seq:
                            pkt_index = id_pair_seq.index(ID)
                            key = icmp_key_seq[pkt_index]
                            icmp_pkt_dict[key] = packet

                    logging.info(f"ICMP Record Updated - Count: {len(icmp_pkt_dict)}")
                    with open('icmp_record.txt', 'w') as f:
                        f.write(str(icmp_pkt_dict))
                        f.flush()

            elif eth_protocol == 1544:  # ARP
                arp_header = packet[settings.ETH_HEADER_LEN: settings.ETH_HEADER_LEN + settings.ARP_HEADER_LEN]
                hw_type, proto_type, hw_size, proto_size, opcode, sender_mac, sender_ip, recv_mac, recv_ip = struct.unpack(
                    '2s2s1s1s2s6s4s6s4s', arp_header)

                if socket.inet_ntoa(recv_ip) == self.host:
                    key, packet_val = gen_arp_key(packet)
                    ip_pair_seq.append((sender_ip, recv_ip))
                    arp_key_seq.append(key)
                    if key not in arp_pkt_dict.keys():
                        arp_pkt_dict[key] = None
                elif socket.inet_ntoa(sender_ip) == self.host and (recv_ip, sender_ip) in ip_pair_seq:
                    pkt_index = ip_pair_seq.index((recv_ip, sender_ip))
                    key = arp_key_seq[pkt_index]
                    arp_pkt_dict[key] = packet

                logging.info(f"ARP Record Updated - Count: {len(arp_pkt_dict)}")
                with open('arp_record.txt', 'w') as f:
                    f.write(str(arp_pkt_dict))
                    f.flush()
            
            else:
                continue
