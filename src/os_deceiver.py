import logging
import json
import os
import socket
import struct
from typing import Dict, Any
import src.settings as settings
from src.Packet import Packet
from src.tcp import TcpConnect

class OsDeceiver:
    def __init__(self, target_host: str, target_os: str, dest: str = None):
        """
        Initialize OS deception with target details.
        """
        self.host = target_host
        self.os = target_os
        self.dest = dest if dest else f"os_record/{self.os}"
        self.conn = TcpConnect(target_host)  # Ensure NIC exists before binding

    def validate_fingerprint_files(self) -> None:
        """
        Ensure all necessary OS fingerprint files exist before running deception.
        """
        required_files = ["arp_record.txt", "tcp_record.txt", "udp_record.txt", "icmp_record.txt"]
        missing_files = []

        for filename in required_files:
            file_path = f"{self.dest}/{filename}"
            if not os.path.exists(file_path):
                missing_files.append(file_path)

        if missing_files:
            logging.error("❌ OS deception failed! Missing required fingerprint files:")
            for f in missing_files:
                logging.error(f"  - {f} (Not Found)")
            logging.info("💡 Run --scan ts first to collect OS fingerprint data.")
            exit(1)

    def load_file(self, pkt_type: str) -> Dict[str, Any]:
        """
        Load OS deception template records from pre-collected fingerprint files.
        """
        file_path = f"{self.dest}/{pkt_type}_record.txt"
        try:
            if not os.path.exists(file_path):
                logging.error(f"❌ Missing fingerprint file: {file_path}")
                return {}

            with open(file_path, 'r') as file:
                packet_data = file.read().strip()
                if not packet_data:
                    logging.warning(f"⚠ {file_path} is empty! OS deception may not work correctly.")
                    return {}
                return json.loads(packet_data)
        except (json.JSONDecodeError, IOError) as e:
            logging.error(f"❌ Error loading {file_path}: {e}")
            return {}

    def os_deceive(self) -> None:
        """
        Perform OS deception based on template packets.
        """
        logging.info(f"🔍 Loading OS deception template for {self.os} from {self.dest}")

        # Validate fingerprint files before proceeding
        self.validate_fingerprint_files()

        template_dict = {p: self.load_file(p) for p in ['arp', 'tcp', 'udp', 'icmp']}
        logging.info(f"✔ OS Fingerprint Templates Loaded Successfully for {self.os}")

        while True:
            try:
                raw_pkt, _ = self.conn.sock.recvfrom(65565)
                pkt = Packet(packet=raw_pkt)
                pkt.unpack()

                # Check if the packet is directed towards the target host
                if (pkt.l3 == 'ip' and pkt.l3_field['dest_IP'] == socket.inet_aton(self.host)) or \
                   (pkt.l3 == 'arp' and pkt.l3_field['recv_ip'] == socket.inet_aton(self.host)):
                    response_pkt = self.generate_deceptive_packet(pkt, template_dict)
                    if response_pkt:
                        logging.info(f"📡 Sending deceptive {pkt.l3} packet.")
                        self.conn.sock.send(response_pkt)
            except Exception as e:
                logging.error(f"❌ Error in OS deception process: {e}")
                continue

    def generate_deceptive_packet(self, req: Packet, template: Dict[str, Any]) -> bytes:
        """
        Generate a deceptive packet based on the request and template.
        """
        try:
            if req.l3 not in template:
                return b''  # No matching fingerprint

            raw_template = template[req.l3].get(req.packet)
            if not raw_template:
                return b''  # No deception data available

            template_pkt = Packet(raw_template)
            template_pkt.unpack()

            # Swap necessary packet fields to mimic the OS
            if req.l3 == 'tcp':
                template_pkt.l2_field.update({'dMAC': req.l2_field['sMAC'], 'sMAC': req.l2_field['dMAC']})
                template_pkt.l3_field.update({'src_IP': req.l3_field['dest_IP'], 'dest_IP': req.l3_field['src_IP']})
                template_pkt.l4_field.update({'src_port': req.l4_field['dest_port'], 'dest_port': req.l4_field['src_port']})

            elif req.l3 == 'icmp':
                template_pkt.l2_field.update({'dMAC': req.l2_field['sMAC'], 'sMAC': req.l2_field['dMAC']})
                template_pkt.l3_field.update({'src_IP': req.l3_field['dest_IP'], 'dest_IP': req.l3_field['src_IP']})
                template_pkt.l4_field.update({'ID': req.l4_field.get('ID', 0), 'seq': req.l4_field.get('seq', 0)})

            elif req.l3 == 'udp':
                template_pkt.l2_field.update({'dMAC': req.l2_field['sMAC'], 'sMAC': req.l2_field['dMAC']})
                template_pkt.l3_field.update({'src_IP': req.l3_field['dest_IP'], 'dest_IP': req.l3_field['src_IP']})

            elif req.l3 == 'arp':
                template_pkt.l2_field.update({'dMAC': req.l2_field['sMAC'], 'sMAC': settings.MAC})
                template_pkt.l3_field.update({
                    'sender_mac': settings.MAC,
                    'sender_ip': socket.inet_aton(settings.HOST),
                    'recv_mac': req.l3_field['sender_mac'],
                    'recv_ip': req.l3_field['sender_ip']
                })
            else:
                return b''  # Unsupported packet type

            template_pkt.pack()
            return template_pkt.packet
        except Exception as e:
            logging.error(f"❌ Error synthesizing deceptive packet: {e}")
            return b''
