import logging
import socket
import struct
import os
from _datetime import datetime, timedelta
from typing import Any

import src.settings as settings
from src.Packet import Packet
from src.tcp import TcpConnect


class OsDeceiver:
    def __init__(self, target_host, camouflage_host, target_os):
        """
        target_host: The IP address being mimicked (Target)
        camouflage_host: The real host running the deception (Camouflage Cloak)
        target_os: The OS fingerprint we are trying to mimic
        """
        self.target_host = target_host
        self.camouflage_host = camouflage_host
        self.target_os = target_os

        # ✅ Create a raw socket connection for packet reception
        self.conn = TcpConnect(self.camouflage_host)

        self.knocking_history = {}
        self.white_list = {}
        self.port_seq = [4441, 5551, 6661]

        # ✅ Ensure OS-specific record directory exists
        self.os_record_path = f"os_record/{self.target_os}"
        if not os.path.exists(self.os_record_path):
            logging.info(f"Creating OS record folder: {self.os_record_path}")
            os.makedirs(self.os_record_path)

    def os_deceive(self):
        """ Performs OS deception by modifying fingerprinting responses """
        logging.info(f"Executing OS deception for {self.target_host}, mimicking {self.target_os}")

        template_dict = {
            "arp": self.load_file("arp"),
            "tcp": self.load_file("tcp"),
            "udp": self.load_file("udp"),
            "icmp": self.load_file("icmp"),
        }

        while True:
            raw_pkt, _ = self.conn.sock.recvfrom(65565)
            pkt = Packet(packet=raw_pkt)
            pkt.unpack()  # ✅ Make sure this is correctly implemented in Packet.py

            proc = pkt.get_proc()

            # ✅ Fix: ARP Handling - Prevent calling non-existent function
            if proc == "arp":
                if not hasattr(pkt, "l3_field") or "recv_ip" not in pkt.l3_field:
                    logging.error("Malformed ARP packet received, skipping...")
                    continue  # Skip if ARP packet structure is incorrect

                # Only respond if the target IP matches
                if pkt.l3_field["recv_ip"] == socket.inet_aton(self.target_host):
                    rsp = self.deceived_pkt_synthesis(proc, pkt, template_dict)
                    if rsp:
                        logging.info(f"Sending deceptive ARP response to {self.target_host}")
                        self.conn.sock.send(rsp)

            # ✅ Fix: Other protocols (TCP, ICMP, UDP)
            elif (pkt.l3 == "ip" and pkt.l3_field["dest_IP"] == socket.inet_aton(self.target_host)):
                rsp = self.deceived_pkt_synthesis(proc, pkt, template_dict)
                if rsp:
                    logging.info(f"Sending deceptive {proc.upper()} response to {self.target_host}")
                    self.conn.sock.send(rsp)

    def load_file(self, pkt_type: str):
        """ Loads stored OS fingerprinting response records """
        file_path = os.path.join(self.os_record_path, f"{pkt_type}_record.txt")

        if not os.path.exists(file_path):
            logging.warning(f"Missing {pkt_type} fingerprint record.")
            return {}

        with open(file_path, "r") as file:
            try:
                return eval(file.readline())  # Safely read the dictionary
            except Exception as e:
                logging.error(f"Error loading {pkt_type} record: {e}")
                return {}

    def deceived_pkt_synthesis(self, proc: str, req: Packet, template: dict):
        """ Generates a deceptive response packet based on stored fingerprints """
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
