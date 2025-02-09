import os
import logging
import socket
import struct
from src.settings import ETH_HEADER_LEN, IP_HEADER_LEN, ARP_HEADER_LEN, ICMP_HEADER_LEN
from src.Packet import Packet
from src.tcp import TcpConnect

class OsDeceiver:
    def __init__(self, target_host, camouflage_host, target_os):
        """
        Initialize the OS Deceiver.
        
        :param target_host: The actual machine we want to mimic (e.g., 192.168.23.201)
        :param camouflage_host: The machine running deception (e.g., 192.168.23.200)
        :param target_os: The OS we want the Nmap scan to detect (e.g., "Win10")
        """
        self.target_host = target_host  # The host we want to disguise
        self.camouflage_host = camouflage_host  # The machine executing deception
        self.target_os = target_os  # OS to mimic
        self.conn = TcpConnect(camouflage_host)  # Camouflage host intercepts traffic
        self.os_record_path = f"os_record/{self.target_os}"
        self.create_os_folder()

    def create_os_folder(self):
        """ Ensure OS-specific record directory exists """
        if not os.path.exists(self.os_record_path):
            logging.info(f"Creating OS record folder: {self.os_record_path}")
            os.makedirs(self.os_record_path)

    def os_deceive(self):
        """ Perform OS deception only for packets targeting the Target Host """
        logging.info(f"[OS Deception] Intercepting OS fingerprinting packets for {self.target_host}...")
        logging.info(f"[OS Deception] Sending deceptive {self.target_os} response...")

        template_dict = {
            "arp": self.load_file("arp"),
            "tcp": self.load_file("tcp"),
            "udp": self.load_file("udp"),
            "icmp": self.load_file("icmp")
        }

        while True:
            raw_pkt, _ = self.conn.sock.recvfrom(65565)
            pkt = Packet(packet=raw_pkt)
            pkt.unpack()
            proc = pkt.get_proc()

            src_ip = socket.inet_ntoa(pkt.l3_field["src_IP"])
            dest_ip = socket.inet_ntoa(pkt.l3_field["dest_IP"])

            # ✅ Ensure we only intercept Nmap scanning packets meant for the Target Host
            if dest_ip != self.target_host:
                logging.warning(f"[OS Deception] Ignoring scan packet from {src_ip} → {dest_ip}. Expected: {self.target_host}")
                continue  # Ignore any traffic not meant for the Target Host

            logging.info(f"[OS Deception] Received fingerprinting request from {src_ip} targeting {dest_ip}")

            # Generate and send deceptive response
            rsp = self.deceived_pkt_synthesis(proc, pkt, template_dict)
            if rsp:
                logging.info(f"[OS Deception] Sending deceptive {proc.upper()} packet to {src_ip}")
                self.conn.sock.send(rsp)

    def load_file(self, pkt_type: str):
        """ Load OS fingerprinting response records """
        file_path = os.path.join(self.os_record_path, f"{pkt_type}_record.txt")

        if not os.path.exists(file_path):
            logging.warning(f"Missing {pkt_type} fingerprint record. Skipping...")
            return {}

        with open(file_path, "r") as file:
            try:
                return eval(file.readline())  # Safely evaluate the stored dictionary
            except Exception as e:
                logging.error(f"Error loading {pkt_type} record: {e}")
                return {}

    def deceived_pkt_synthesis(self, proc: str, req: Packet, template: dict):
        """ Generate a deceptive response packet based on stored fingerprints """
        key, _ = gen_key(proc, req.packet)

        try:
            raw_template = template[proc][key]
        except KeyError:
            logging.warning(f"No deception template found for {proc}.")
            return None

        template_pkt = Packet(raw_template)
        template_pkt.unpack()

        # Swap source & destination details
        template_pkt.l2_field["dMAC"] = req.l2_field["sMAC"]
        template_pkt.l2_field["sMAC"] = req.l2_field["dMAC"]
        template_pkt.l3_field["src_IP"] = req.l3_field["dest_IP"]
        template_pkt.l3_field["dest_IP"] = req.l3_field["src_IP"]

        if proc == "tcp":
            template_pkt.l4_field["src_port"] = req.l4_field["dest_port"]
            template_pkt.l4_field["dest_port"] = req.l4_field["src_port"]
            template_pkt.l4_field["seq"] = req.l4_field["ack_num"]
            template_pkt.l4_field["ack_num"] = req.l4_field["seq"] + 1

        elif proc == "icmp":
            template_pkt.l4_field["ID"] = req.l4_field["ID"]
            template_pkt.l4_field["seq"] = req.l4_field["seq"]

        elif proc == "udp":
            template_pkt.l4_field["ID"] = 0
            template_pkt.l4_field["seq"] = 0

        elif proc == "arp":
            template_pkt.l3_field["sender_mac"] = settings.mac
            template_pkt.l3_field["sender_ip"] = socket.inet_aton(self.target_host)
            template_pkt.l3_field["recv_mac"] = req.l3_field["sender_mac"]
            template_pkt.l3_field["recv_ip"] = req.l3_field["sender_ip"]

        template_pkt.pack()
        return template_pkt.packet
