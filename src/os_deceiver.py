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
        self.target_host_str = target_host  # Keep original IP as a string
        self.target_host = socket.inet_aton(target_host)  # Convert IP to bytes
        self.target_os = target_os
        self.conn = TcpConnect(target_host)
        self.os_record_path = f"os_record/{self.target_os}"
        self.capture_timeout = 120  # Timeout for fingerprint capture (2 min)

        # Ensure OS-specific record directory exists
        if not os.path.exists(self.os_record_path):
            logging.info(f"Creating OS record folder: {self.os_record_path}")
            os.makedirs(self.os_record_path)

        logging.info(f"Initialized OsDeceiver for {self.target_host_str} ({self.target_os})")

    def os_record(self, max_packets=100):
        """
        Captures OS fingerprinting packets (ARP, ICMP) and exits after reaching max_packets or timeout.
        :param max_packets: Number of packets to capture before exiting (default: 100).
        """
        logging.info(f"Intercepting OS fingerprinting packets on {settings.NIC} for {self.target_host_str}")
        logging.info(f"Max Packets: {max_packets}, Timeout: {self.capture_timeout}s")

        arp_pkt_dict = {}
        icmp_pkt_dict = {}

        arp_record_file = os.path.join(self.os_record_path, "arp_record.txt")
        icmp_record_file = os.path.join(self.os_record_path, "icmp_record.txt")

        start_time = time.time()
        packet_count = 0

        try:
            while packet_count < max_packets:
                if time.time() - start_time > self.capture_timeout:
                    logging.info("Timeout reached. Exiting OS fingerprinting mode.")
                    break

                packet, addr = self.conn.sock.recvfrom(65565)
                logging.debug(f"Packet received from {addr}")

                eth_protocol, src_IP, dest_IP, PROTOCOL = self._parse_ethernet_ip(packet)

                logging.debug(f"Packet Details: Src={socket.inet_ntoa(src_IP)}, Dest={socket.inet_ntoa(dest_IP)}, Protocol={PROTOCOL}")

                # Ensure packet is meant for target host
                if dest_IP != self.target_host:
                    continue  # Ignore non-target packets

                if PROTOCOL == 1:  # ICMP packets
                    key, _ = self.gen_icmp_key(packet)
                    icmp_pkt_dict[key] = packet
                    packet_count += 1
                    logging.info(f"ICMP Packet Captured ({packet_count})")

                    with open(icmp_record_file, "w") as f:
                        f.write(str(icmp_pkt_dict))

                elif eth_protocol == 1544:  # ARP packets
                    key, _ = self.gen_arp_key(packet)
                    arp_pkt_dict[key] = packet
                    packet_count += 1
                    logging.info(f"ARP Packet Captured ({packet_count})")

                    with open(arp_record_file, "w") as f:
                        f.write(str(arp_pkt_dict))

            if packet_count == 0:
                logging.warning("No packets captured! Ensure network interface is in promiscuous mode and packets are flowing.")

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

    def os_deceive(self):
        """
        Performs OS deception by modifying fingerprinting responses.
        Dynamically detects Nmap scanner and responds to it.
        """
        logging.info(f"Executing OS deception for {self.target_host_str}, mimicking {self.target_os}...")

        template_dict = {
            'arp': self.load_file("arp"),
            'tcp': self.load_file("tcp"),
            'udp': self.load_file("udp"),
            'icmp': self.load_file("icmp")
        }

        while True:
            try:
                raw_pkt, _ = self.conn.sock.recvfrom(65565)
                pkt = Packet(packet=raw_pkt)
                pkt.unpack()

                # Ensure responses go to correct scanning host
                if pkt.l3_field['dest_IP'] != self.target_host:
                    continue  # Ignore non-target packets

                proc = pkt.get_proc()
                response_pkt = self.deceived_pkt_synthesis(proc, pkt, template_dict)

                if response_pkt:
                    logging.info(f"Sending deceptive {proc.upper()} packet.")
                    self.conn.sock.send(response_pkt)
            except Exception as e:
                logging.error(f"Error in os_deceive(): {e}")

    def load_file(self, pkt_type: str):
        """ Loads OS fingerprinting response records. """
        file_path = os.path.join(self.os_record_path, f"{pkt_type}_record.txt")

        if not os.path.exists(file_path):
            logging.warning(f"Missing {pkt_type} fingerprint record. Skipping...")
            return {}

        try:
            with open(file_path, 'r') as file:
                return eval(file.readline())  # Read stored dictionary
        except Exception as e:
            logging.error(f"Error loading {pkt_type} record: {e}")
            return {}

    def deceived_pkt_synthesis(self, proc: str, req: Packet, template: dict):
        """ Generates a deceptive response packet based on stored fingerprints. """
        key, _ = self.gen_key(proc, req.packet)

        try:
            raw_template = template[proc][key]
        except KeyError:
            logging.warning(f"No deception template found for {proc}.")
            return None

        template_pkt = Packet(raw_template)
        template_pkt.unpack()

        # Ensure responses go back to the correct scanning host
        template_pkt.l2_field['dMAC'] = req.l2_field['sMAC']
        template_pkt.l2_field['sMAC'] = settings.mac  # Use our spoofed MAC
        template_pkt.l3_field['src_IP'] = req.l3_field['dest_IP']
        template_pkt.l3_field['dest_IP'] = req.l3_field['src_IP']

        template_pkt.pack()
        return template_pkt.packet

    def gen_key(self, proc, packet):
        """ Generates a key for identifying fingerprint packets. """
        if proc == 'tcp':
            return self.gen_tcp_key(packet)
        elif proc == 'udp':
            return self.gen_udp_key(packet)
        elif proc == 'icmp':
            return self.gen_icmp_key(packet)
        elif proc == 'arp':
            return self.gen_arp_key(packet)
        else:
            return None, None
