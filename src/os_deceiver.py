import logging
import json
import socket
import struct
from datetime import datetime, timedelta
from typing import List, Any
import src.settings as settings
from src.Packet import Packet
from src.tcp import TcpConnect

class OsDeceiver:
    def __init__(self, target_host, target_os, dest=None):
        """Initialize OS deception with target details."""
        self.host = target_host
        self.os = target_os
        self.conn = TcpConnect(target_host)  # Ensure NIC exists before binding
        self.white_list = {}
        self.port_seq = [4441, 5551, 6661]
        self.dest = dest

    def load_file(self, pkt_type: str):
        """Load OS deception template records from file."""
        file_path = f"os_record/{self.os}/{pkt_type}_record.txt"

        try:
            with open(file_path, 'r') as file:
                packet_data = file.read().strip()
                if not packet_data:
                    return {}  # Empty file case
                packet_dict = json.loads(packet_data)
                return {k: v for k, v in packet_dict.items() if v is not None}

        except (json.JSONDecodeError, FileNotFoundError, IOError) as e:
            logging.error(f"Error loading {file_path}: {e}")
            return {}

    def store_rsp(self):
        """Store responses to specific TCP ports."""
        rsp = {}
        while True:
            packet, _ = self.conn.sock.recvfrom(65565)
            eth_protocol = struct.unpack('!H', packet[12:14])[0]

            if eth_protocol == 0x0800:  # IPv4
                ip_header = packet[settings.ETH_HEADER_LEN: settings.ETH_HEADER_LEN + settings.IP_HEADER_LEN]
                _, _, _, _, _, _, PROTOCOL, _, src_IP, dest_IP = struct.unpack('!BBHHHBBH4s4s', ip_header)

                if PROTOCOL == 6 and src_IP == socket.inet_aton(self.host):  # TCP
                    pkt = Packet(packet)
                    pkt.unpack()

                    src_port = pkt.l4_field.get('src_port')  # Use .get() for safety
                    if src_port:
                        rsp.setdefault(src_port, []).append(packet)

                        with open('rsp_record.txt', 'w') as f:
                            json.dump(rsp, f)  # Use JSON for better storage

    def os_deceive(self):
        """Perform OS deception based on template packets."""
        logging.info(f'Loading OS deception template for {self.os}')
        template_dict = {p: self.load_file(p) for p in ['arp', 'tcp', 'udp', 'icmp']}

        while True:
            raw_pkt, _ = self.conn.sock.recvfrom(65565)
            pkt = Packet(packet=raw_pkt)
            pkt.unpack()

            proc = pkt.get_proc()
            if proc == 'tcp' and pkt.l3_field['dest_IP'] == Packet.ip_str2byte(self.host):
                if pkt.l4_field['dest_port'] in settings.FREE_PORT:
                    continue  # Ignore free ports

            if (pkt.l3 == 'ip' and pkt.l3_field['dest_IP'] == socket.inet_aton(self.host)) or \
                    (pkt.l3 == 'arp' and pkt.l3_field['recv_ip'] == socket.inet_aton(self.host)):

                rsp = deceived_pkt_synthesis(proc, pkt, template_dict)
                if rsp:
                    logging.info(f'Sending deceptive {proc} packet.')
                    self.conn.sock.send(rsp)

def deceived_pkt_synthesis(proc: str, req: Packet, template: dict):
    """Generate a deceptive packet based on the request and template."""
    key, _ = gen_key(proc, req.packet)
    try:
        raw_template = template[proc][key]
    except KeyError:
        return None  # No deception data available

    template_pkt = Packet(raw_template)
    template_pkt.unpack()

    if proc == 'tcp':
        template_pkt.l2_field.update({'dMAC': req.l2_field['sMAC'], 'sMAC': req.l2_field['dMAC']})
        template_pkt.l3_field.update({'src_IP': req.l3_field['dest_IP'], 'dest_IP': req.l3_field['src_IP']})
        template_pkt.l4_field.update({'src_port': req.l4_field['dest_port'], 'dest_port': req.l4_field['src_port']})

    elif proc == 'icmp':
        template_pkt.l2_field.update({'dMAC': req.l2_field['sMAC'], 'sMAC': req.l2_field['dMAC']})
        template_pkt.l3_field.update({'src_IP': req.l3_field['dest_IP'], 'dest_IP': req.l3_field['src_IP']})
        template_pkt.l4_field.update({'ID': req.l4_field['ID'], 'seq': req.l4_field['seq']})

    elif proc == 'udp':
        template_pkt.l2_field.update({'dMAC': req.l2_field['sMAC'], 'sMAC': req.l2_field['dMAC']})
        template_pkt.l3_field.update({'src_IP': req.l3_field['dest_IP'], 'dest_IP': req.l3_field['src_IP']})

    elif proc == 'arp':
        template_pkt.l2_field.update({'dMAC': req.l2_field['sMAC'], 'sMAC': settings.mac})
        template_pkt.l3_field.update({
            'sender_mac': settings.mac,
            'sender_ip': socket.inet_aton(settings.host),
            'recv_mac': req.l3_field['sender_mac'],
            'recv_ip': req.l3_field['sender_ip']
        })

    else:
        return None  # Unsupported packet type

    template_pkt.pack()
    return template_pkt.packet

def gen_key(proc, packet):
    """Generate a key based on protocol type."""
    return {
        'tcp': gen_tcp_key,
        'udp': gen_udp_key,
        'icmp': gen_icmp_key,
        'arp': gen_arp_key
    }.get(proc, lambda x: (None, None))(packet)
   
