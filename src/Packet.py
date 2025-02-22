import struct
import socket
import logging
import src.settings as settings

class Packet:
    """ Handles unpacking and storing network packet details. """

    def __init__(self, packet):
        self.packet = packet
        self.l2_field = {}
        self.l3_field = {}
        self.l4_field = {}

    def unpack(self):
        """ Unpack the Ethernet frame to determine the protocol. """
        try:
            eth_header = self.packet[:settings.ETH_HEADER_LEN]
            eth = struct.unpack("!6s6sH", eth_header)
            eth_protocol = socket.ntohs(eth[2])

            self.l2_field["sMAC"] = eth[1]  # Source MAC
            self.l2_field["dMAC"] = eth[0]  # Destination MAC
            self.l2_field["protocol"] = eth_protocol

            if eth_protocol == 0x0800:  # IPv4
                self.unpack_ip_header()
            elif eth_protocol == 0x0806:  # ARP
                self.unpack_arp_header()
        except Exception as e:
            logging.error(f"Error unpacking Ethernet frame: {e}")

    def unpack_ip_header(self):
        """ Unpacks the IPv4 header. """
        try:
            ip_header = self.packet[settings.ETH_HEADER_LEN: settings.ETH_HEADER_LEN + settings.IP_HEADER_LEN]
            unpacked = struct.unpack("!BBHHHBBH4s4s", ip_header)

            self.l3_field["version"] = unpacked[0] >> 4
            self.l3_field["src_IP"] = socket.inet_ntoa(unpacked[8])  # Convert bytes to string
            self.l3_field["dest_IP"] = socket.inet_ntoa(unpacked[9])  # Convert bytes to string

            # Debugging logs
            logging.info(f"Raw src_IP: {unpacked[8]} | Converted: {self.l3_field['src_IP']}")
            logging.info(f"Raw dest_IP: {unpacked[9]} | Converted: {self.l3_field['dest_IP']}")
            
            self.l3_field["protocol"] = unpacked[6]

            if self.l3_field["protocol"] == 1:  # ICMP
                self.unpack_icmp_header()
            elif self.l3_field["protocol"] == 6:  # TCP
                self.unpack_tcp_header()
        except Exception as e:
            logging.error(f"Error unpacking IP header: {e}")

    def unpack_tcp_header(self):
        """ Unpacks the TCP header. """
        try:
            tcp_header = self.packet[
                settings.ETH_HEADER_LEN + settings.IP_HEADER_LEN:
                settings.ETH_HEADER_LEN + settings.IP_HEADER_LEN + settings.TCP_HEADER_LEN
            ]
            unpacked = struct.unpack("!HHLLBBHHH", tcp_header)

            self.l4_field["src_port"] = unpacked[0]
            self.l4_field["dest_port"] = unpacked[1]
            self.l4_field["seq"] = unpacked[2]
            self.l4_field["ack"] = unpacked[3]
            self.l4_field["flags"] = unpacked[5]
        except Exception as e:
            logging.error(f"Error unpacking TCP header: {e}")

    def unpack_icmp_header(self):
        """ Unpacks the ICMP header. """
        try:
            icmp_header = self.packet[
                settings.ETH_HEADER_LEN + settings.IP_HEADER_LEN:
                settings.ETH_HEADER_LEN + settings.IP_HEADER_LEN + settings.ICMP_HEADER_LEN
            ]
            unpacked = struct.unpack("!BBH", icmp_header)

            self.l4_field["icmp_type"] = unpacked[0]
            self.l4_field["icmp_code"] = unpacked[1]
        except Exception as e:
            logging.error(f"Error unpacking ICMP header: {e}")

    def unpack_arp_header(self):
        """ Unpacks the ARP header. """
        try:
            arp_header = self.packet[settings.ETH_HEADER_LEN: settings.ETH_HEADER_LEN + settings.ARP_HEADER_LEN]
            unpacked = struct.unpack("!HHBBH6s4s6s4s", arp_header)

            self.l3_field["hw_type"] = unpacked[0]
            self.l3_field["proto_type"] = unpacked[1]
            self.l3_field["opcode"] = unpacked[4]
            self.l3_field["sender_mac"] = unpacked[5]
            self.l3_field["sender_ip"] = unpacked[6]
            self.l3_field["target_mac"] = unpacked[7]
            self.l3_field["target_ip"] = unpacked[8]
        except Exception as e:
            logging.error(f"Error unpacking ARP header: {e}")
