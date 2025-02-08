import logging
import random
import socket
import struct
import os
import sys
from datetime import datetime

# Ensure correct module path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# Import settings and dependencies
try:
    import settings
except ImportError:
    logging.warning("Failed to import settings.py. Using default values.")
    settings = None

from Packet import Packet
from tcp import TcpConnect

class OsDeceiver:
    def __init__(self, host, os_name):
        self.host = host
        self.os = os_name.strip().lower() if os_name else "unknown"  # Handle only non-None OS names
        self.conn = TcpConnect(host)
        self.knocking_history = {}
        self.white_list = {}
        self.port_seq = [4441, 5551, 6661]  # Hardcoded port knocking sequence

    def os_record(self, output_path=None):
        """Records incoming OS fingerprinting packets and saves them."""
        if output_path is None:
            output_path = settings.TARGET_OS_OUTPUT_DIR

        os.makedirs(output_path, exist_ok=True)

        record_file = os.path.join(output_path, f"{self.os}_record.txt")
        pkt_dict = {}
        port_pair_seq = []
        key_seq = []

        logging.info(f"Recording OS fingerprints to: {record_file}")

        while True:
            packet, _ = self.conn.sock.recvfrom(65565)
            eth_header = packet[:settings.ETH_HEADER_LEN]
            eth = struct.unpack("!6s6sH", eth_header)
            eth_protocol = socket.ntohs(eth[2])

            if eth_protocol == 8:  # IP packets
                ip_header = packet[settings.ETH_HEADER_LEN : settings.ETH_HEADER_LEN + settings.IP_HEADER_LEN]
                _, _, _, _, _, _, PROTOCOL, _, src_IP, dest_IP = struct.unpack("!BBHHHBBH4s4s", ip_header)

                if PROTOCOL == 6:  # TCP
                    tcp_header = packet[
                        settings.ETH_HEADER_LEN + settings.IP_HEADER_LEN : settings.ETH_HEADER_LEN
                        + settings.IP_HEADER_LEN
                        + settings.TCP_HEADER_LEN
                    ]
                    src_port, dest_port, seq, ack_num, offset, flags, window, checksum, urgent_ptr = struct.unpack(
                        "!HHLLBBHHH", tcp_header
                    )

                    if dest_IP == socket.inet_aton(self.host):
                        key, packet_val = self.gen_tcp_key(packet)
                        if key not in pkt_dict:
                            pkt_dict[key] = None
                        port_pair_seq.append((src_port, dest_port))
                        key_seq.append(key)

                    elif src_IP == socket.inet_aton(self.host) and (dest_port, src_port) in port_pair_seq:
                        pkt_index = port_pair_seq.index((dest_port, src_port))
                        key = key_seq[pkt_index]
                        if pkt_dict[key] is None:
                            logging.info("Captured OS fingerprinting response packet.")
                            pkt_dict[key] = packet

                    # Save to file
                    with open(record_file, "w") as f:
                        f.write(str(pkt_dict))

    def template_synthesis(self, output_path=None):
        """Generates and stores template synthesis for the given OS."""
        if output_path is None:
            output_path = settings.TARGET_OS_OUTPUT_DIR

        os.makedirs(output_path, exist_ok=True)

        # Create a template synthesis based on the OS name
        template_file = os.path.join(output_path, f"{self.os}_template.txt")
        
        # Define the content of your template
        template_content = f"""Template Synthesis for OS: {self.os}
Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
---------------------------------------
- Host: {self.host}
- Known Ports: {self.port_seq}
- Additional settings or configurations can go here.
"""

        logging.info(f"Storing template synthesis to: {template_file}")
        
        # Write the template to the specified file
        with open(template_file, "w") as f:
            f.write(template_content)
