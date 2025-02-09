import os
import logging
import socket
import struct
import time
from datetime import datetime
import src.settings as settings
from src.Packet import Packet
from src.tcp import TcpConnect


class OsDeceiver:
    def __init__(self, target_host, target_os):
        """
        Initialize OS Deceiver for fingerprint collection & deception.
        :param target_host: The host to mimic (e.g., "192.168.23.201")
        :param target_os: The OS to mimic (e.g., "win10", "centos")
        """
        self.target_host = target_host
        self.target_os = target_os
        self.conn = TcpConnect(target_host)
        self.os_record_path = f"os_record/{self.target_os}"
        self.nmap_scanner_ip = None  # Track Nmap scanning IP dynamically

        # Ensure OS-specific record directory exists
        if not os.path.exists(self.os_record_path):
            logging.info(f"Creating OS record folder: {self.os_record_path}")
            os.makedirs(self.os_record_path)

    def os_record(self, max_packets=100, timeout=120):
        """
        Captures OS fingerprinting packets (ARP, ICMP) and exits after reaching max_packets or timeout.
        :param max_packets: Number of packets to capture before exiting (default: 100).
        :param timeout: Capture timeout in seconds (default: 120 seconds / 2 minutes).
        """
        logging.info(f"Intercepting OS fingerprinting packets for {self.target_host}")

        arp_pkt_dict = {}
        icmp_pkt_dict = {}

        arp_record_file = os.path.join(self.os_record_path, "arp_record.txt")
        icmp_record_file = os.path.join(self.os_record_path, "icmp_record.txt")

        start_time = time.time()  # Start time tracking
        packet_count = 0

        try:
            while packet_count < max_packets:
                if time.time() - start_time > timeout:  # Timeout condition
                    logging.info("Timeout reached. Stopping capture.")
                    break

                packet, addr = self.conn.sock.recvfrom(65565)
                src_ip = addr[0]  # Capture source IP
                
                if not self.nmap_scanner_ip:
                    self.nmap_scanner_ip = src_ip  # Store first detected scanner IP
                    logging.info(f"Detected Nmap scanning host: {self.nmap_scanner_ip}")
                
                eth_header = packet[:settings.ETH_HEADER_LEN]
                eth_protocol = struct.unpack("!H", eth_header[12:14])[0]

                if eth_protocol == 8:  # IPv4 packets
                    ip_header = packet[settings.ETH_HEADER_LEN: settings.ETH_HEADER_LEN + settings.IP_HEADER_LEN]
                    _, _, _, _, _, _, protocol, _, src_ip_bytes, dest_ip_bytes = struct.unpack("!BBHHHBBH4s4s", ip_header)
                    dest_ip = socket.inet_ntoa(dest_ip_bytes)

                    if dest_ip != self.target_host:
                        continue  # Ignore non-target packets

                    if protocol == 1:  # ICMP packets
                        key, _ = self.gen_icmp_key(packet)
                        icmp_pkt_dict[key] = packet
                        packet_count += 1
                        logging.info(f"Captured ICMP Packet ({packet_count})")
                        with open(icmp_record_file, "w") as f:
                            f.write(str(icmp_pkt_dict))
                
                elif eth_protocol == 1544:  # ARP packets
                    key, _ = self.gen_arp_key(packet)
                    arp_pkt_dict[key] = packet
                    packet_count += 1
                    logging.info(f"Captured ARP Packet ({packet_count})")
                    with open(arp_record_file, "w") as f:
                        f.write(str(arp_pkt_dict))
            
            logging.info("OS Fingerprinting Completed.")
        
        except KeyboardInterrupt:
            logging.info("User interrupted capture.")
        except Exception as e:
            logging.error(f"Error while capturing packets: {e}")

    def os_deceive(self):
        """
        Performs OS deception by modifying fingerprinting responses.
        Dynamically detects Nmap scanner and responds to it.
        """
        logging.info(f"Executing OS deception for {self.target_host}, mimicking {self.target_os}")

        template_dict = {
            'arp': self.load_file("arp"),
            'tcp': self.load_file("tcp"),
            'udp': self.load_file("udp"),
            'icmp': self.load_file("icmp")
        }

        while True:
            raw_pkt, addr = self.conn.sock.recvfrom(65565)
            src_ip = addr[0]
            
            if not self.nmap_scanner_ip:
                self.nmap_scanner_ip = src_ip  # Detect first scanner IP

            if src_ip != self.nmap_scanner_ip:
                continue  # Ignore non-scanner packets
            
            pkt = Packet(packet=raw_pkt)
            pkt.unpack()

            if pkt.l3_field['dest_IP'] != socket.inet_aton(self.target_host):
                continue  # Ignore non-target packets

            proc = pkt.get_proc()
            response_pkt = self.deceived_pkt_synthesis(proc, pkt, template_dict)

            if response_pkt:
                logging.info(f"Sending deceptive {proc.upper()} packet to {src_ip}")
                self.conn.sock.sendto(response_pkt, (src_ip, 0))

    def load_file(self, pkt_type: str):
        file_path = os.path.join(self.os_record_path, f"{pkt_type}_record.txt")
        if not os.path.exists(file_path):
            logging.warning(f"Missing {pkt_type} fingerprint record. Skipping...")
            return {}
        try:
            with open(file_path, 'r') as file:
                return eval(file.readline())
        except Exception as e:
            logging.error(f"Error loading {pkt_type} record: {e}")
            return {}

    def deceived_pkt_synthesis(self, proc: str, req: Packet, template: dict):
        key, _ = self.gen_key(proc, req.packet)
        try:
            raw_template = template[proc][key]
        except KeyError:
            logging.warning(f"No deception template found for {proc}.")
            return None

        template_pkt = Packet(raw_template)
        template_pkt.unpack()
        template_pkt.l3_field['src_IP'] = req.l3_field['dest_IP']
        template_pkt.l3_field['dest_IP'] = req.l3_field['src_IP']
        template_pkt.pack()
        return template_pkt.packet
