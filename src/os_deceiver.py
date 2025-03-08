import logging
import json
import os
import socket
import struct
from datetime import datetime, timedelta
from typing import List, Dict, Any
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
        self.conn = TcpConnect(target_host)  # Ensure NIC exists before binding
        self.white_list: Dict[str, Any] = {}
        self.port_seq: List[int] = [4441, 5551, 6661]
        self.dest = dest

        # Ensure OS record path exists
        self.os_record_path = f"/home/user/Camouflage-Cloak/os_record/{self.os}"
        os.makedirs(self.os_record_path, exist_ok=True)

    def load_file(self, pkt_type: str) -> Dict[str, Any]:
        """
        Load OS deception template records from file.
        """
        file_path = f"{self.os_record_path}/{pkt_type}_record.txt"

        try:
            # Check if file exists and has correct permissions
            if not os.path.exists(file_path):
                logging.error(f"❌ Error: {file_path} not found.")
                return {}

            if not os.access(file_path, os.R_OK):
                logging.error(f"❌ Permission error: Cannot read {file_path}.")
                return {}

            with open(file_path, 'r', encoding='utf-8') as file:
                packet_data = file.read().strip()
                if not packet_data:
                    logging.warning(f"⚠ Warning: {file_path} is empty.")
                    return {}

                packet_dict = json.loads(packet_data)
                return {k: v for k, v in packet_dict.items() if v is not None}

        except (json.JSONDecodeError, FileNotFoundError, IOError, PermissionError) as e:
            logging.error(f"❌ Error loading {file_path}: {e}")
            return {}

    def store_rsp(self) -> None:
        """
        Store responses to specific TCP ports.
        """
        rsp: Dict[int, List[bytes]] = {}
        while True:
            try:
                packet, _ = self.conn.sock.recvfrom(65565)
                eth_protocol = struct.unpack('!H', packet[12:14])[0]

                if eth_protocol == 0x0800:  # IPv4
                    ip_header = packet[settings.ETH_HEADER_LEN: settings.ETH_HEADER_LEN + settings.IP_HEADER_LEN]
                    fields = struct.unpack('!BBHHHBBH4s4s', ip_header)
                    PROTOCOL, src_IP, dest_IP = fields[6], fields[8], fields[9]

                    if PROTOCOL == 6 and src_IP == socket.inet_aton(self.host):  # TCP
                        pkt = Packet(packet)
                        pkt.unpack()
                        src_port = pkt.l4_field.get('src_port')  # Use .get() for safety
                        if src_port:
                            rsp.setdefault(src_port, []).append(packet)
                            with open('rsp_record.txt', 'w', encoding='utf-8') as f:
                                json.dump(rsp, f)  # Use JSON for better storage
            except Exception as e:
                logging.error(f"❌ Error storing response packet: {e}")
                continue

    def os_deceive(self) -> None:
        """
        Perform OS deception based on template packets.
        """
        logging.info(f'📌 Loading OS deception template for {self.os}')
        template_dict = {p: self.load_file(p) for p in ['arp', 'tcp', 'udp', 'icmp']}

        while True:
            try:
                raw_pkt, _ = self.conn.sock.recvfrom(65565)
                pkt = Packet(packet=raw_pkt)
                pkt.unpack()

                if (pkt.l3 == 'ip' and pkt.l3_field['dest_IP'] == socket.inet_aton(self.host)) or \
                   (pkt.l3 == 'arp' and pkt.l3_field['recv_ip'] == socket.inet_aton(self.host)):
                    rsp = deceived_pkt_synthesis(pkt, template_dict)
                    if rsp:
                        logging.info(f'📌 Sending deceptive {pkt.l3} packet.')
                        self.conn.sock.send(rsp)
            except Exception as e:
                logging.error(f"❌ Error in OS deception process: {e}")
                continue

def deceived_pkt_synthesis(req: Packet, template: Dict[str, Any]) -> bytes:
    """
    Generate a deceptive packet based on the request and template.
    """
    try:
        raw_template = template.get(req.l3, {}).get(req.packet)
        if not raw_template:
            return b''  # No deception data available
        
        template_pkt = Packet(raw_template)
        template_pkt.unpack()

        if req.l3 == 'tcp':
            template_pkt.l2_field.update({'dMAC': req.l2_field['sMAC'], 'sMAC': req.l2_field['dMAC']})
            template_pkt.l3_field.update({'src_IP': req.l3_field['dest_IP'], 'dest_IP': req.l3_field['src_IP']})
            template_pkt.l4_field.update({'src_port': req.l4_field['dest_port'], 'dest_port': req.l4_field['src_port']})

        elif req.l3 == 'icmp':
            template_pkt.l2_field.update({'dMAC': req.l2_field['sMAC'], 'sMAC': req.l2_field['dMAC']})
            template_pkt.l3_field.update({'src_IP': req.l3_field['dest_IP'], 'dest_IP': req.l3_field['src_IP']})
            template_pkt.l4_field.update({'ID': req.l4_field['ID'], 'seq': req.l4_field['seq']})

        elif req.l3 == 'udp':
            template_pkt.l2_field.update({'dMAC': req.l2_field['sMAC'], 'sMAC': req.l2_field['dMAC']})
            template_pkt.l3_field.update({'src_IP': req.l3_field['dest_IP'], 'dest_IP': req.l3_field['src_IP']})
            template_pkt.l4_field.update({'src_port': req.l4_field['dest_port'], 'dest_port': req.l4_field['src_port']})

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
