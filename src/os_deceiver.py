import os
import logging
import socket
import struct
import time
import threading
import src.settings as settings
from src.Packet import Packet
from src.tcp import TcpConnect

class OsDeceiver:
    def __init__(self, target_host, target_os, dest):
        """
        Initialize OS Deceiver with retrieved fingerprint data.
        """
        self.target_host_str = target_host
        self.target_host = socket.inet_aton(target_host)  # Convert IP to bytes
        self.target_os = target_os
        self.conn = TcpConnect(target_host)
        self.os_record_path = os.path.join(dest, self.target_os)  # Retrieve from --dest directory
        self.running = False  # Flag to track deception state
        self.thread = None  # Thread for deception process
        self.packet_data = {}  # Stores retrieved OS fingerprint packets

        # Ensure OS fingerprint directory exists
        if not os.path.exists(self.os_record_path):
            logging.error(f"OS fingerprint for '{self.target_os}' not found in '{dest}'.")
            logging.error(f"Run '--scan ts' first to collect fingerprint data.")
            raise FileNotFoundError(f"Missing OS fingerprint directory: {self.os_record_path}")

        # Load OS fingerprint data before starting deception
        self._load_fingerprint_data()

        logging.info(f"OsDeceiver initialized for {self.target_host_str} (Mimic: {self.target_os})")

    def _load_fingerprint_data(self):
        """
        Loads fingerprint data from stored files.
        """
        fingerprint_files = {
            "arp": os.path.join(self.os_record_path, "arp_record.txt"),
            "icmp": os.path.join(self.os_record_path, "icmp_record.txt"),
            "tcp": os.path.join(self.os_record_path, "tcp_record.txt"),
            "udp": os.path.join(self.os_record_path, "udp_record.txt"),
        }

        for proto, file_path in fingerprint_files.items():
            if not os.path.exists(file_path):
                logging.error(f"Missing fingerprint data for {proto.upper()} packets.")
                logging.error(f"Ensure '{file_path}' exists and run '--scan ts' if needed.")
                raise FileNotFoundError(f"Missing required fingerprint file: {file_path}")

            with open(file_path, "r") as f:
                self.packet_data[proto] = f.read().splitlines()  # Load packet data

        logging.info(f"Loaded OS fingerprint data from {self.os_record_path}")

    def os_deceive(self):
        """
        Starts OS Deception in a separate thread using retrieved fingerprint data.
        """
        logging.info(f"Starting OS Deception for {self.target_host_str}, mimicking {self.target_os}")
        self.running = True
        self.thread = threading.Thread(target=self._deception_loop)
        self.thread.start()

    def _deception_loop(self):
        """
        Internal method to send retrieved packets as OS deception.
        """
        while self.running:
            try:
                if not self.packet_data:
                    logging.error("No fingerprint data available for deception.")
                    break

                # Simulating deception based on fingerprinted packets
                for proto, packets in self.packet_data.items():
                    if not packets:
                        continue

                    for packet in packets:
                        if not self.running:
                            break  # Stop deception if flagged

                        logging.debug(f"Sending {proto.upper()} packet for deception: {packet}")
                        # Simulated deception (Replace this with actual packet transmission)
                        time.sleep(1)

            except Exception as e:
                logging.error(f"OS Deception encountered an error: {e}")
                self.running = False

    def stop(self):
        """
        Stops OS Deception.
        """
        logging.info("Stopping OS Deception...")
        self.running = False  # Set flag to stop loop
        if self.thread and self.thread.is_alive():
            self.thread.join()  # Ensure the thread stops
        logging.info("OS Deception successfully stopped.")

    def os_record(self, max_packets=100):
        """
        Captures OS fingerprinting packets (ARP, ICMP, TCP, UDP) and logs them.
        """
        logging.info(f"Capturing packets on {settings.NIC} for {self.target_host_str} (Max: {max_packets}, Timeout: 2 min)")

        packet_files = {
            "arp": os.path.join(self.os_record_path, "arp_record.txt"),
            "icmp": os.path.join(self.os_record_path, "icmp_record.txt"),
            "tcp": os.path.join(self.os_record_path, "tcp_record.txt"),
            "udp": os.path.join(self.os_record_path, "udp_record.txt")
        }

        start_time = time.time()
        packet_count = 0

        try:
            while packet_count < max_packets:
                if time.time() - start_time > 120:
                    logging.info("Timeout reached. Exiting OS fingerprinting mode.")
                    break

                packet, addr = self.conn.sock.recvfrom(65565)
                logging.debug(f"Packet received from {addr}")

                eth_protocol, src_IP, dest_IP, PROTOCOL = self._parse_ethernet_ip(packet)

                if dest_IP != self.target_host:
                    continue

                proto_type = None
                if PROTOCOL == 1:
                    proto_type = "icmp"
                elif PROTOCOL == 6:
                    proto_type = "tcp"
                elif PROTOCOL == 17:
                    proto_type = "udp"
                elif eth_protocol == 1544:
                    proto_type = "arp"

                if proto_type:
                    with open(packet_files[proto_type], "a") as f:
                        f.write(str(packet) + "\n")

                    packet_count += 1
                    logging.info(f"Captured {proto_type.upper()} Packet ({packet_count})")

            if packet_count == 0:
                logging.warning("No packets captured! Check network interface settings and traffic.")

            logging.info(f"OS Fingerprinting Completed. Captured {packet_count} packets.")

        except KeyboardInterrupt:
            logging.info("User interrupted capture. Exiting...")
        except Exception as e:
            logging.error(f"Error while capturing packets: {e}")

        logging.info("Returning to command mode.")

    def _parse_ethernet_ip(self, packet):
        """Parses Ethernet and IP headers."""
        try:
            eth_header = packet[:settings.ETH_HEADER_LEN]
            eth = struct.unpack("!6s6sH", eth_header)
            eth_protocol = socket.ntohs(eth[2])

            ip_header = packet[settings.ETH_HEADER_LEN: settings.ETH_HEADER_LEN + settings.IP_HEADER_LEN]
            _, _, _, _, _, _, PROTOCOL, _, src_IP, dest_IP = struct.unpack("!BBHHHBBH4s4s", ip_header)

            return eth_protocol, src_IP, dest_IP, PROTOCOL
        except struct.error as e:
            logging.error(f"Error parsing Ethernet/IP headers: {e}")
            return None, None, None, None
