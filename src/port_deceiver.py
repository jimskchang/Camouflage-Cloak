import logging
import socket
import struct
import src.settings as settings
from src.tcp import TcpConnect, getIPChecksum, getTCPChecksum

# Protocol Constants
ETH_TYPE_IP = 0x0800
PROTO_TCP = 6
PROTO_ICMP = 1

logging.basicConfig(level=logging.INFO)


class PortDeceiver:
    def __init__(self, host):
        self.host = host
        self.conn = TcpConnect(host)

    def send_packet(self, recv_flags, reply_flags):
        """Listens for packets and replies based on received TCP flags."""
        while True:
            try:
                packet, _ = self.conn.sock.recvfrom(65565)
                eth_protocol, src_ip, dest_ip, protocol, eth_header, ip_header = self.extract_headers(packet)

                if eth_protocol != ETH_TYPE_IP or protocol != PROTO_TCP or dest_ip != socket.inet_aton(self.conn.dip):
                    continue

                tcp_header = self.extract_tcp_header(packet)
                if tcp_header is None:
                    continue

                src_port, dest_port, seq, ack_num, flags = tcp_header

                if flags not in recv_flags:
                    continue

                logging.info(f"Received TCP packet with flag: {flags}")

                reply_seq = ack_num
                reply_ack = seq + 1
                reply_src_port = dest_port
                reply_dest_port = src_port

                num_recv = len(recv_flags)
                for i in range(num_recv):
                    if flags == recv_flags[i] and reply_flags[i] != 0:
                        reply_tcp_header = self.conn.build_tcp_header_from_reply(
                            5, reply_seq, reply_ack, reply_src_port, reply_dest_port, src_ip, dest_ip, reply_flags[i]
                        )
                        reply_packet = eth_header + ip_header + reply_tcp_header
                        self.conn.sock.send(reply_packet)
                        logging.info(f"Replied with flag: {reply_flags[i]}")

                return True

            except Exception as e:
                logging.error(f"Error in send_packet: {e}")

    def deceive_ps_hs(self, port_status):
        """Handles port deception based on open/closed status."""
        port_flag = 18 if port_status == "open" else 20
        logging.info(f"Deceiving port as {port_status}")

        while True:
            try:
                packet, _ = self.conn.sock.recvfrom(65565)
                eth_protocol, src_ip, dest_ip, protocol, eth_header, ip_header = self.extract_headers(packet)

                if eth_protocol != ETH_TYPE_IP or dest_ip != socket.inet_aton(self.conn.dip):
                    continue

                if protocol == PROTO_TCP:
                    if port_status == "record":
                        self.record_packet(packet, "pkt_record.txt")
                        continue

                    tcp_header = self.extract_tcp_header(packet)
                    if tcp_header is None:
                        continue

                    src_port, dest_port, seq, ack_num, flags = tcp_header
                    reply_seq = ack_num
                    reply_ack = seq + 1
                    reply_src_port = dest_port
                    reply_dest_port = src_port

                    if flags == 2:  # SYN received
                        logging.info("Received SYN, replying with ACK/RST")
                        reply_flags = port_flag
                    elif flags == 16:  # ACK received
                        logging.info("Received ACK, replying with RST")
                        reply_flags = 4
                    elif port_status == "close":
                        reply_flags = port_flag
                    else:
                        continue

                    reply_tcp_header = self.conn.build_tcp_header_from_reply(
                        5, reply_seq, reply_ack, reply_src_port, reply_dest_port, src_ip, dest_ip, reply_flags
                    )
                    reply_packet = eth_header + ip_header + reply_tcp_header
                    self.conn.sock.send(reply_packet)
                    continue

                elif protocol == PROTO_ICMP:
                    if port_status == "record":
                        continue
                    self.handle_icmp_reply(packet, eth_header, ip_header)

            except Exception as e:
                logging.error(f"Error in deceive_ps_hs: {e}")

    def extract_headers(self, packet):
        """Extracts Ethernet and IP headers."""
        try:
            eth_header = packet[:settings.ETH_HEADER_LEN]
            eth = struct.unpack("!6s6sH", eth_header)
            eth_protocol = socket.ntohs(eth[2])

            if eth_protocol == ETH_TYPE_IP:
                ip_header = packet[settings.ETH_HEADER_LEN: settings.ETH_HEADER_LEN + settings.IP_HEADER_LEN]
                _, _, _, _, _, _, protocol, _, src_ip, dest_ip = struct.unpack("!BBHHHBBH4s4s", ip_header)

                if dest_ip != socket.inet_aton(self.conn.dip):
                    return None, None, None, None, None, None

                reply_eth_header = struct.pack("!6s6sH", eth[1], eth[0], eth[2])
                reply_ip_header = self.build_ip_header(dest_ip, src_ip, protocol)

                return eth_protocol, src_ip, dest_ip, protocol, reply_eth_header, reply_ip_header

        except struct.error:
            logging.error("Invalid packet format in extract_headers.")
            return None, None, None, None, None, None

    def extract_tcp_header(self, packet):
        """Extracts TCP header from the packet."""
        try:
            tcp_header = packet[settings.ETH_HEADER_LEN + settings.IP_HEADER_LEN: settings.ETH_HEADER_LEN +
                                settings.IP_HEADER_LEN + settings.TCP_HEADER_LEN]
            src_port, dest_port, seq, ack_num, offset, flags, _, _, _ = struct.unpack("!HHLLBBHHH", tcp_header)

            return src_port, dest_port, seq, ack_num, flags
        except struct.error:
            logging.error("Invalid TCP header format.")
            return None

    def build_ip_header(self, src_ip, dest_ip, protocol):
        """Constructs an IP header."""
        try:
            pktID = 456  # Arbitrary number
            reply_ttl = 64
            total_len = 40
            check_sum_of_hdr = 0

            ip_header = struct.pack("!BBHHHBBH4s4s", 69, 0, total_len, pktID, 0, reply_ttl, protocol,
                                    check_sum_of_hdr, src_ip, dest_ip)
            check_sum_of_hdr = getIPChecksum(ip_header)

            return struct.pack("!BBHHHBBH4s4s", 69, 0, total_len, pktID, 0, reply_ttl, protocol,
                               check_sum_of_hdr, src_ip, dest_ip)
        except struct.error:
            logging.error("Error in building IP header.")
            return None

    def handle_icmp_reply(self, packet, eth_header, ip_header):
        """Handles ICMP echo reply."""
        try:
            icmp_header = packet[settings.ETH_HEADER_LEN + settings.IP_HEADER_LEN: settings.ETH_HEADER_LEN +
                                 settings.IP_HEADER_LEN + settings.ICMP_HEADER_LEN]
            data = packet[settings.ETH_HEADER_LEN + settings.IP_HEADER_LEN + settings.ICMP_HEADER_LEN:]
            icmp_type, code, _, pktID, seq = struct.unpack("BbHHh", icmp_header)

            if icmp_type in {8, 13}:  # Echo Request or Timestamp Request
                reply_type = 0 if icmp_type == 8 else 14
                reply_icmp_header = struct.pack("BbHHh", reply_type, code, 0, pktID, seq)
                checksum = getTCPChecksum(reply_icmp_header + data)
                reply_icmp_header = struct.pack("BbHHh", reply_type, code, checksum, pktID, seq)

                reply_packet = eth_header + ip_header + reply_icmp_header + data
                self.conn.sock.send(reply_packet)

        except struct.error:
            logging.error("Invalid ICMP header format.")

    def record_packet(self, packet, filename):
        """Records a packet to a file."""
        with open(filename, "a") as f:
            f.write(str(packet) + "\n")
