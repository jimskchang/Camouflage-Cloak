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
        self.os_record_path = dest if os.path.basename(dest) == target_os else os.path.join(dest, target_os)
        self.running = False
        self.thread = None
        self.packet_data = {}

        if mode == "deception":
            if not os.path.exists(self.os_record_path):
                logging.error(f"OS fingerprint for '{self.target_os}' not found in '{dest}'.")
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
