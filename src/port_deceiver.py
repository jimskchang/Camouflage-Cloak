import logging
import socket
import struct
from src import settings
from src.tcp import TcpConnect, calculate_ip_checksum, calculate_tcp_checksum


class PortDeceiver:
    """Handles deceptive port scanning responses."""

    def __init__(self, host: str):
        self.host = host
        self.conn = TcpConnect(host)

    def send_packet(self, recv_flags, reply_flags):
        """Intercepts packets and sends deceptive responses."""
        while True:
            try:
                packet, _ = self.conn.sock.recvfrom(65565)
            except socket.error as e:
                logging.error(f"Socket error: {e}")
                continue

            eth_protocol, src_IP, dest_IP, PROTOCOL = self._parse_ethernet_ip(packet)

            if eth_protocol != 8 or PROTOCOL != 6:  # Only handle TCP
                continue

            # Build Ethernet header
            reply_eth_header = self._build_eth_header(packet)

            # Build IP header
            reply_ip_header = self._build_ip_header(packet, src_IP, dest_IP)

            tcp_header = packet[settings.ETH_HEADER_LEN + settings.IP_HEADER_LEN: settings.ETH_HEADER_LEN
                                + settings.IP_HEADER_LEN + settings.TCP_HEADER_LEN]
            src_port, dest_port, seq, ack_num, offset, flags, _, _, _ = struct.unpack('!HHLLBBHHH', tcp_header)

            if flags not in recv_flags:
                continue

            logging.info(f"Received flag: {flags}")

            reply_seq = ack_num
            reply_ack_num = seq + 1
            reply_src_port = dest_port
            reply_dest_port = src_port

            num_recv = len(recv_flags)
            for i in range(num_recv):
                if flags == recv_flags[i] and reply_flags[i] != 0:
                    reply_tcp_header = self.conn.build_tcp_header_from_reply(
                        5, reply_seq, reply_ack_num, reply_src_port, reply_dest_port, src_IP, dest_IP, reply_flags[i]
                    )
                    packet = reply_eth_header + reply_ip_header + reply_tcp_header
                    self.conn.sock.send(packet)
                    logging.info(f"Replied with flag: {reply_flags[i]}")

            return True

    def deceive_ps_hs(self, port_status: str):
        """Deceives port scanning tools."""
        port_flag = 18 if port_status == "open" else 20
        logging.info(f"Deceiving {port_status} port.")

        while True:
            try:
                packet, _ = self.conn.sock.recvfrom(65565)
            except socket.error as e:
                logging.error(f"Socket error: {e}")
                continue

            eth_protocol, src_IP, dest_IP, PROTOCOL = self._parse_ethernet_ip(packet)

            if eth_protocol != 8:
                continue

            # Build Ethernet header
            reply_eth_header = self._build_eth_header(packet)

            # Build IP header
            reply_ip_header = self._build_ip_header(packet, src_IP, dest_IP)

            if PROTOCOL == 6:  # TCP
                if port_status == "record":
                    with open("pkt_record.txt", "a", encoding="utf-8") as f:
                        f.write(str(packet) + "\n")
                    continue

                tcp_header = packet[settings.ETH_HEADER_LEN + settings.IP_HEADER_LEN: settings.ETH_HEADER_LEN +
                                    settings.IP_HEADER_LEN + settings.TCP_HEADER_LEN]
                src_port, dest_port, seq, ack_num, offset, flags, _, _, _ = struct.unpack("!HHLLBBHHH", tcp_header)

                reply_seq = ack_num
                reply_ack_num = seq + 1
                reply_src_port = dest_port
                reply_dest_port = src_port

                if flags == 2:  # SYN
                    logging.info("Received SYN, sending deceptive response.")
                    reply_tcp_header = self.conn.build_tcp_header_from_reply(
                        5, reply_seq, reply_ack_num, reply_src_port, reply_dest_port, src_IP, dest_IP, port_flag
                    )
                elif flags == 16:  # ACK
                    logging.info("Received ACK, sending deceptive response.")
                    reply_tcp_header = self.conn.build_tcp_header_from_reply(
                        5, reply_seq, reply_ack_num, reply_src_port, reply_dest_port, src_IP, dest_IP, 4
                    )
                elif port_status == "close":
                    reply_tcp_header = self.conn.build_tcp_header_from_reply(
                        5, reply_seq, reply_ack_num, reply_src_port, reply_dest_port, src_IP, dest_IP, port_flag
                    )
                else:
                    continue

                packet = reply_eth_header + reply_ip_header + reply_tcp_header
                self.conn.sock.send(packet)
                continue

            elif PROTOCOL == 1:  # ICMP
                if port_status == "record":
                    continue

                icmp_header = packet[settings.ETH_HEADER_LEN + settings.IP_HEADER_LEN:
                                     settings.ETH_HEADER_LEN + settings.IP_HEADER_LEN + settings.ICMP_HEADER_LEN]
                data = packet[settings.ETH_HEADER_LEN + settings.IP_HEADER_LEN + settings.ICMP_HEADER_LEN:]
                icmp_type, code, checksum, pktID, seq = struct.unpack("BbHHh", icmp_header)
                pktID = 456

                if icmp_type == 8:
                    logging.info("Received ICMP Echo Request, replying with Echo Reply.")
                    icmp_type = 0
                elif icmp_type == 13:
                    logging.info("Received ICMP Timestamp Request, replying with Timestamp Reply.")
                    icmp_type = 14

                checksum = 0
                pseudo_packet = struct.pack("BbHHh", icmp_type, code, checksum, pktID, seq) + data
                checksum = calculate_tcp_checksum(pseudo_packet)
                reply_icmp_header = struct.pack("BbHHh", icmp_type, code, checksum, pktID, seq)

                packet = reply_eth_header + reply_ip_header + reply_icmp_header + data
                self.conn.sock.send(packet)
                continue

            else:
                continue

    def _parse_ethernet_ip(self, packet):
        """Parses Ethernet and IP headers."""
        eth_header = packet[:settings.ETH_HEADER_LEN]
        eth = struct.unpack("!6s6sH", eth_header)
        eth_protocol = socket.ntohs(eth[2])

        ip_header = packet[settings.ETH_HEADER_LEN: settings.ETH_HEADER_LEN + settings.IP_HEADER_LEN]
        _, _, _, _, _, _, PROTOCOL, _, src_IP, dest_IP = struct.unpack("!BBHHHBBH4s4s", ip_header)

        return eth_protocol, src_IP, dest_IP, PROTOCOL

    def _build_eth_header(self, packet):
        """Builds an Ethernet header for response packets."""
        eth_header = packet[:settings.ETH_HEADER_LEN]
        eth = struct.unpack("!6s6sH", eth_header)
        return struct.pack("!6s6sH", eth[1], eth[0], eth[2])  # Swap src and dest MAC

    def _build_ip_header(self, packet, src_IP, dest_IP):
        """Builds an IP header for response packets."""
        ip_header = packet[settings.ETH_HEADER_LEN: settings.ETH_HEADER_LEN + settings.IP_HEADER_LEN]
        IHL_VERSION, TYPE_OF_SERVICE, _, pktID, FRAGMENT_STATUS, TIME_TO_LIVE, PROTOCOL, _, _, _ = \
            struct.unpack("!BBHHHBBH4s4s", ip_header)

        pktID = 456  # Arbitrary ID
        check_sum_of_hdr = 0
        reply_ttl = TIME_TO_LIVE + 1
        total_len = 40

        reply_ip_header = struct.pack("!BBHHHBBH4s4s", IHL_VERSION, TYPE_OF_SERVICE, total_len, pktID,
                                      FRAGMENT_STATUS, reply_ttl, PROTOCOL, check_sum_of_hdr, dest_IP, src_IP)
        check_sum_of_hdr = calculate_ip_checksum(reply_ip_header)

        return struct.pack("!BBHHHBBH4s4s", IHL_VERSION, TYPE_OF_SERVICE, total_len, pktID,
                           FRAGMENT_STATUS, reply_ttl, PROTOCOL, check_sum_of_hdr, dest_IP, src_IP)
