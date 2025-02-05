import logging
import socket
import struct
import os

import src.settings as settings
from src.tcp import TcpConnect
from src.Packet import Packet
from src.utils import (
    calculate_checksum,
    convert_mac_to_bytes,
    convert_ip_to_bytes,
    convert_bytes_to_ip
)


class PortDeceiver:
    def __init__(self, host):
        self.host = host
        self.conn = TcpConnect(host)

    def send_packet(self, recv_flags, reply_flags, output_path=None):
        """Handles packet replies for deceptive port responses."""
        if not output_path:
            output_path = os.path.join(settings.TARGET_OS_OUTPUT_DIR, "pkt_record.log")

        # ✅ Ensure directory exists
        os.makedirs(os.path.dirname(output_path), exist_ok=True)

        logging.info(f"Recording deceptive packets in {output_path}")

        while True:
            try:
                packet, _ = self.conn.sock.recvfrom(65565)
                pkt = Packet(packet)
                pkt.unpack()
            except Exception as e:
                logging.error(f"Failed to unpack packet: {e}")
                continue  # Skip processing this packet

            if not pkt.l3_field or 'dest_IP' not in pkt.l3_field:
                logging.warning("Packet missing L3 fields, skipping.")
                continue

            if pkt.l3_field['dest_IP'] != settings.TARGET_SERVER:
                continue

            if pkt.l4 != "tcp":
                continue  # Only handle TCP packets

            flags = pkt.l4_field.get('flags', 0)
            if flags in recv_flags:
                logging.info(f"Received TCP flag={flags}, preparing response.")
            else:
                continue

            if 'ack_num' not in pkt.l4_field or 'seq' not in pkt.l4_field:
                logging.warning("Missing TCP fields (seq/ack_num), skipping packet.")
                continue

            reply_seq = pkt.l4_field['ack_num']
            reply_ack_num = pkt.l4_field['seq'] + 1
            reply_src_port = pkt.l4_field['dest_port']
            reply_dest_port = pkt.l4_field['src_port']

            num_recv = len(recv_flags)
            for i in range(num_recv):
                if flags == recv_flags[i]:
                    if reply_flags[i] == 0:
                        continue
                    reply_tcp_header = self.conn.build_tcp_header_from_reply(
                        5, reply_seq, reply_ack_num, reply_src_port, reply_dest_port,
                        pkt.l3_field['dest_IP'], pkt.l3_field['src_IP'], reply_flags[i]
                    )
                    response_packet = self.build_eth_ip_header(pkt.l3_field['dest_IP'], pkt.l3_field['src_IP']) + reply_tcp_header
                    self.conn.sock.send(response_packet)
                    logging.info(f"Sent TCP response with flag={reply_flags[i]}")

            # Save to file
            with open(output_path, 'a') as f:
                f.write(response_packet.hex() + '\n')

    def deceive_ps_hs(self, port_status, output_path=None):
        """Deceives port scanning techniques."""
        if not output_path:
            output_path = os.path.join(settings.TARGET_OS_OUTPUT_DIR, "deception_log.log")

        # ✅ Ensure directory exists
        os.makedirs(os.path.dirname(output_path), exist_ok=True)

        logging.info(f"Deceiving port scan as {port_status}, logging responses to {output_path}")

        if port_status == 'open':
            port_flag = 18  # SYN-ACK
        elif port_status == 'close':
            port_flag = 20  # RST-ACK
        else:
            logging.error("Invalid port status. Use 'open' or 'close'.")
            return

        while True:
            try:
                packet, _ = self.conn.sock.recvfrom(65565)
                pkt = Packet(packet)
                pkt.unpack()
            except Exception as e:
                logging.error(f"Failed to unpack packet: {e}")
                continue  # Skip processing this packet

            if not pkt.l3_field or 'dest_IP' not in pkt.l3_field:
                logging.warning("Packet missing L3 fields, skipping.")
                continue

            if pkt.l3_field['dest_IP'] != settings.TARGET_SERVER:
                continue

            if pkt.l4 != "tcp":
                continue  # Ignore non-TCP packets

            flags = pkt.l4_field.get('flags', 0)
            if 'ack_num' not in pkt.l4_field or 'seq' not in pkt.l4_field:
                logging.warning("Missing TCP fields (seq/ack_num), skipping packet.")
                continue

            reply_seq = pkt.l4_field['ack_num']
            reply_ack_num = pkt.l4_field['seq'] + 1
            reply_src_port = pkt.l4_field['dest_port']
            reply_dest_port = pkt.l4_field['src_port']

            if flags == 2:  # SYN received
                logging.info("Received SYN, sending deceptive response.")
                reply_tcp_header = self.conn.build_tcp_header_from_reply(
                    5, reply_seq, reply_ack_num, reply_src_port, reply_dest_port,
                    pkt.l3_field['dest_IP'], pkt.l3_field['src_IP'], port_flag
                )
            elif flags == 16:  # ACK received
                logging.info("Received ACK, sending RST.")
                reply_tcp_header = self.conn.build_tcp_header_from_reply(
                    5, reply_seq, reply_ack_num, reply_src_port, reply_dest_port,
                    pkt.l3_field['dest_IP'], pkt.l3_field['src_IP'], 4  # RST
                )
            else:
                continue

            response_packet = self.build_eth_ip_header(pkt.l3_field['dest_IP'], pkt.l3_field['src_IP']) + reply_tcp_header
            self.conn.sock.send(response_packet)

            # Save to log
            with open(output_path, 'a') as f:
                f.write(response_packet.hex() + '\n')

    def build_eth_ip_header(self, src_ip, dest_ip):
        """Builds Ethernet and IP headers for deceptive responses."""
        eth_header = struct.pack('!6s6sH', 
                                 convert_mac_to_bytes(settings.CLOAK_MAC), 
                                 convert_mac_to_bytes(settings.TARGET_SERVER_MAC), 
                                 0x0800)  # IP Protocol

        src_ip_bytes = convert_ip_to_bytes(src_ip)
        dest_ip_bytes = convert_ip_to_bytes(dest_ip)

        ip_header = struct.pack('!BBHHHBBH4s4s', 
                                69, 0, 40, 456, 0, 64, 6, 0, 
                                src_ip_bytes, dest_ip_bytes)  # Default IP Header

        check_sum_of_hdr = calculate_checksum(ip_header)
        ip_header = struct.pack('!BBHHHBBH4s4s', 
                                69, 0, 40, 456, 0, 64, 6, check_sum_of_hdr, 
                                src_ip_bytes, dest_ip_bytes)

        return eth_header + ip_header
