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
    def __init__(self, target_host, target_os, dest, mode="deception"):
        """
        Initialize OS Deceiver.
        """
        self.target_host_str = target_host
        self.target_host = socket.inet_aton(target_host)
        self.target_os = target_os
        self.conn = TcpConnect(target_host)

        # Ensure OS name is not appended twice
        if os.path.basename(dest) == target_os:
            self.os_record_path = dest
        else:
            self.os_record_path = os.path.join(dest, target_os)

        self.running = False
        self.thread = None
        self.packet_data = {}

        if mode == "deception":
            if not os.path.exists(self.os_record_path):
                logging.error(f"OS fingerprint for '{self.target_os}' not found in '{self.os_record_path}'.")
                logging.error("Run '--scan ts' first to collect fingerprint data.")
                raise FileNotFoundError(f"Missing OS fingerprint directory: {self.os_record_path}")
            self._load_fingerprint_data()
        elif mode == "scan":
            os.makedirs(self.os_record_path, exist_ok=True)
            logging.info(f"Created OS fingerprint directory: {self.os_record_path}")

        logging.info(f"OsDeceiver initialized for {self.target_host_str} (Mode: {mode})")

    def _load_fingerprint_data(self):
        """
        Loads fingerprint data from stored files for OS deception.
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
                self.packet_data[proto] = f.read().splitlines()

        logging.info(f"Loaded OS fingerprint data from {self.os_record_path}")

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

