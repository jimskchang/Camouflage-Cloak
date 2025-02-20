import os
import logging
import socket
import struct
import threading
import time
from src import settings
from src.tcp import TcpConnect, calculate_ip_checksum
from src.Packet import Packet  # Ensure Packet class is imported

class PortDeceiver:
    """Handles deceptive port scanning responses."""

    def __init__(self, host: str, port_status: str, dest: str):
        """
        Initialize Port Deceiver with stored fingerprint data.
        """
        self.host = socket.inet_aton(host)  # Convert host IP to bytes
        self.conn = TcpConnect(host)
        self.port_status = port_status
        self.deception_data_path = os.path.join(dest, f"port_{port_status}")  # Retrieve deception data from --dest
        self.running = False  # Flag for controlling deception process
        self.thread = None  # Thread for deception loop
        self.packet_data = []  # Stores retrieved port fingerprint packets

        # Ensure port deception data exists
        if not os.path.exists(self.deception_data_path):
            logging.error(f"Port deception data for '{port_status}' not found in '{dest}'.")
            logging.error(f"Run '--scan ts' first to collect port fingerprinting data.")
            raise FileNotFoundError(f"Missing port deception directory: {self.deception_data_path}")

        # Load fingerprint data
        self._load_fingerprint_data()

        logging.info(f"PortDeceiver initialized for {host} (Port Status: {port_status})")

    def _load_fingerprint_data(self):
        """
        Loads fingerprint data from stored files.
        """
        fingerprint_file = os.path.join(self.deception_data_path, "port_record.txt")

        if not os.path.exists(fingerprint_file):
            logging.error(f"Missing fingerprint data for port deception.")
            logging.error(f"Ensure '{fingerprint_file}' exists and run '--scan ts' if needed.")
            raise FileNotFoundError(f"Missing required fingerprint file: {fingerprint_file}")

        with open(fingerprint_file, "r") as f:
            self.packet_data = f.read().splitlines()  # Load packet data

        logging.info(f"Loaded Port fingerprint data from {self.deception_data_path}")

    def port_deceive(self):
        """Starts Port Deception in a separate thread."""
        logging.info(f"Starting Port Deception for {self.host}, status: {self.port_status}")
        self.running = True
        self.thread = threading.Thread(target=self._deception_loop)
        self.thread.start()

    def _deception_loop(self):
        """Internal method to run deception logic until stopped."""
        while self.running:
            try:
                packet, _ = self.conn.sock.recvfrom(65565)
                if not self.running:
                    break

                eth_protocol, src_IP, dest_IP, PROTOCOL = self._parse_ethernet_ip(packet)
                if eth_protocol != 8 or PROTOCOL != 6:  # Only handle TCP packets
                    continue

                reply_eth_header = self._build_eth_header(packet)
                reply_ip_header = self._build_ip_header(packet, src_IP, dest_IP)

                tcp_header = packet[settings.ETH_HEADER_LEN + settings.IP_HEADER_LEN: 
                                    settings.ETH_HEADER_LEN + settings.IP_HEADER_LEN + settings.TCP_HEADER_LEN]
                src_port, dest_port, seq, ack_num, offset, flags, _, _, _ = struct.unpack("!HHLLBBHHH", tcp_header)

                reply_seq = ack_num
                reply_ack_num = seq + 1
                reply_src_port = dest_port
                reply_dest_port = src_port

                if flags == 2:  # SYN Received
                    logging.info("Received SYN, sending deceptive response.")
                    reply_tcp_header = self.conn.build_tcp_header_from_reply(
                        5, reply_seq, reply_ack_num, reply_src_port, reply_dest_port, src_IP, dest_IP, 
                        18 if self.port_status == "open" else 20
                    )
                elif flags == 16:  # ACK Received
                    logging.info("Received ACK, sending deceptive response.")
                    reply_tcp_header = self.conn.build_tcp_header_from_reply(
                        5, reply_seq, reply_ack_num, reply_src_port, reply_dest_port, src_IP, dest_IP, 4
                    )
                elif self.port_status == "close":
                    reply_tcp_header = self.conn.build_tcp_header_from_reply(
                        5, reply_seq, reply_ack_num, reply_src_port, reply_dest_port, src_IP, dest_IP, 20
                    )
                else:
                    continue

                # Send deceptive response
                packet = reply_eth_header + reply_ip_header + reply_tcp_header
                self.conn.sock.send(packet)

            except Exception as e:
                logging.error(f"Port Deception encountered an error: {e}")
                self.running = False

    def stop(self):
        """Stops Port Deception."""
        logging.info("Stopping Port Deception...")
        self.running = False
        if self.thread and self.thread.is_alive():
            self.thread.join()  # Ensure the thread stops
        logging.info("Port Deception successfully stopped.")

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
