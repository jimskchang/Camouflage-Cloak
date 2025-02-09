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

        # Ensure OS-specific record directory exists
        if not os.path.exists(self.os_record_path):
            logging.info(f"📁 Creating OS record folder: {self.os_record_path}")
            os.makedirs(self.os_record_path)

    def os_deceive(self):
        """
        Performs OS deception by modifying fingerprinting responses.
        Intercepts and sends back packets mimicking the specified OS.
        """
        logging.info(f"🚀 Executing OS deception for {self.target_host}, mimicking {self.target_os}...")

        # Load fingerprinting response templates
        template_dict = {
            'arp': self.load_file("arp"),
            'tcp': self.load_file("tcp"),
            'udp': self.load_file("udp"),
            'icmp': self.load_file("icmp")
        }

        while True:
            raw_pkt, _ = self.conn.sock.recvfrom(65565)
            pkt = Packet(packet=raw_pkt)
            pkt.unpack()

            # 🔍 Detect the Nmap scanning host dynamically
            nmap_scanner_ip = socket.inet_ntoa(pkt.l3_field['src_IP'])

            # ✅ Ensure responses go back to the Nmap scanner
            if pkt.l3_field['dest_IP'] != socket.inet_aton(self.target_host):
                continue  # Ignore non-target packets

            proc = pkt.get_proc()
            response_pkt = self.deceived_pkt_synthesis(proc, pkt, template_dict)

            if response_pkt:
                logging.info(f"📨 Sending deceptive {proc.upper()} packet to Nmap scanner: {nmap_scanner_ip}")
                self.conn.sock.send(response_pkt)

    def load_file(self, pkt_type: str):
        """ Loads OS fingerprinting response records. """
        file_path = os.path.join(self.os_record_path, f"{pkt_type}_record.txt")

        if not os.path.exists(file_path):
            logging.warning(f"⚠️ Missing {pkt_type} fingerprint record. Skipping...")
            return {}

        try:
            with open(file_path, 'r') as file:
                return eval(file.readline())  # Read stored dictionary
        except Exception as e:
            logging.error(f"⚠️ Error loading {pkt_type} record: {e}")
            return {}

    def deceived_pkt_synthesis(self, proc: str, req: Packet, template: dict):
        """ Generates a deceptive response packet based on stored fingerprints. """
        key, _ = self.gen_key(proc, req.packet)

        try:
            raw_template = template[proc][key]
        except KeyError:
            logging.warning(f"⚠️ No deception template found for {proc}.")
            return None

        template_pkt = Packet(raw_template)
        template_pkt.unpack()

        # 🔄 Ensure responses go back to the correct Nmap scanning host
        template_pkt.l2_field['dMAC'] = req.l2_field['sMAC']
        template_pkt.l2_field['sMAC'] = settings.mac  # Use our spoofed MAC
        template_pkt.l3_field['src_IP'] = req.l3_field['dest_IP']
        template_pkt.l3_field['dest_IP'] = req.l3_field['src_IP']

        if proc == 'tcp':
            template_pkt.l4_field['src_port'] = req.l4_field['dest_port']
            template_pkt.l4_field['dest_port'] = req.l4_field['src_port']
            template_pkt.l4_field['seq'] = req.l4_field['ack_num']
            template_pkt.l4_field['ack_num'] = req.l4_field['seq'] + 1

        elif proc == 'icmp':
            template_pkt.l4_field['ID'] = req.l4_field['ID']
            template_pkt.l4_field['seq'] = req.l4_field['seq']

        elif proc == 'udp':
            template_pkt.l4_field['ID'] = 0
            template_pkt.l4_field['seq'] = 0

        elif proc == 'arp':
            template_pkt.l3_field['sender_mac'] = settings.mac
            template_pkt.l3_field['sender_ip'] = socket.inet_aton(self.target_host)
            template_pkt.l3_field['recv_mac'] = req.l3_field['sender_mac']
            template_pkt.l3_field['recv_ip'] = req.l3_field['sender_ip']

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
