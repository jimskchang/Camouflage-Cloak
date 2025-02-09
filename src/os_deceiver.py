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
        self.capture_timeout = 120  # Timeout for fingerprint capture (2 minutes)

        # Ensure OS-specific record directory exists
        if not os.path.exists(self.os_record_path):
            logging.info(f"Creating OS record folder: {self.os_record_path}")
            os.makedirs(self.os_record_path)

    def os_record(self, max_packets=100):
        """
        Captures OS fingerprinting packets (ARP, ICMP) and exits after reaching max_packets or timeout.
        :param max_packets: Number of packets to capture before exiting (default: 100).
        """
        logging.info(f"Intercepting OS fingerprinting packets for {self.target_host} (Max: {max_packets}, Timeout: {self.capture_timeout}s)")

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

                packet, _ = self.conn.sock.recvfrom(65565)
                pkt = Packet(packet=packet)
                pkt.unpack()  # Ensure headers are correctly extracted

                # Process IPv4 packets
                if pkt.l2_field.get("protocol") == 0x0800:  # IPv4
                    if pkt.l3_field.get("dest_IP") != socket.inet_aton(self.target_host):
                        continue  # Ignore non-target packets

                    if pkt.l3_field.get("protocol") == 1:  # ICMP
                        key = self.gen_icmp_key(packet)
                        icmp_pkt_dict[key] = packet
                        packet_count += 1
                        logging.info(f"ICMP Packet Captured ({packet_count})")

                        with open(icmp_record_file, "w") as f:
                            f.write(str(icmp_pkt_dict))

                # Process ARP packets
                elif pkt.l2_field.get("protocol") == 0x0806:  # ARP
                    key = self.gen_arp_key(packet)
                    arp_pkt_dict[key] = packet
                    packet_count += 1
                    logging.info(f"ARP Packet Captured ({packet_count})")

                    with open(arp_record_file, "w") as f:
                        f.write(str(arp_pkt_dict))

            logging.info(f"OS Fingerprinting Completed. Captured {packet_count} packets.")

        except KeyboardInterrupt:
            logging.info("User interrupted capture. Exiting...")
        except Exception as e:
            logging.error(f"Error while capturing packets: {e}")

        logging.info("Returning to command mode.")

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
            raw_pkt, _ = self.conn.sock.recvfrom(65565)
            pkt = Packet(packet=raw_pkt)
            pkt.unpack()  # Ensure all headers are unpacked correctly

            # Ignore packets not destined for the target host
            if pkt.l3_field.get("dest_IP") != socket.inet_aton(self.target_host):
                continue

            proc = pkt.get_proc()
            response_pkt = self.deceived_pkt_synthesis(proc, pkt, template_dict)

            if response_pkt:
                logging.info(f"Sending deceptive {proc.upper()} packet.")
                self.conn.sock.send(response_pkt)

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

    def gen_arp_key(self, packet: bytes):
        """ Generate ARP fingerprinting key """
        arp_header = packet[settings.ETH_HEADER_LEN: settings.ETH_HEADER_LEN + settings.ARP_HEADER_LEN]
        key = arp_header[:8]
        return key, packet

    def gen_icmp_key(self, packet: bytes):
        """ Generate ICMP fingerprinting key """
        ip_header = packet[settings.ETH_HEADER_LEN: settings.ETH_HEADER_LEN + settings.IP_HEADER_LEN]
        icmp_header = packet[settings.ETH_HEADER_LEN + settings.IP_HEADER_LEN:
                             settings.ETH_HEADER_LEN + settings.IP_HEADER_LEN + settings.ICMP_HEADER_LEN]
        key = ip_header[12:16] + icmp_header[:4]
        return key, packet
