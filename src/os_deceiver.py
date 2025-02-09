import os
import logging
import socket
import struct
from src.settings import ETH_HEADER_LEN, IP_HEADER_LEN, ARP_HEADER_LEN
from src.Packet import Packet
from src.tcp import TcpConnect

class OsDeceiver:
    def __init__(self, host, target_os):
        self.host = host
        self.target_os = target_os
        self.conn = TcpConnect(host)
        self.os_record_path = f"os_record/{self.target_os}"
        self.create_os_folder()

    def create_os_folder(self):
        """ Ensure OS-specific record directory exists """
        if not os.path.exists(self.os_record_path):
            logging.info(f"Creating OS record folder: {self.os_record_path}")
            os.makedirs(self.os_record_path)

    def os_deceive(self):
        """ Performs OS deception by modifying fingerprinting responses """
        logging.info(f"[OS Deception] Intercepting OS fingerprinting packets for {self.host}...")
        logging.info(f"[OS Deception] Sending deceptive Windows 10 response...")

        # Load OS-specific packet templates
        template_dict = {
            'arp': self.load_file("arp"),
            'tcp': self.load_file("tcp"),
            'udp': self.load_file("udp"),
            'icmp': self.load_file("icmp")
        }

        while True:
            raw_pkt, _ = self.conn.sock.recvfrom(65565)
            pkt = Packet(raw_pkt)

            # Ensure correct unpacking of ARP
            eth_header = raw_pkt[:ETH_HEADER_LEN]
            eth = struct.unpack("!6s6sH", eth_header)
            eth_protocol = socket.ntohs(eth[2])

            if eth_protocol == 1544:  # ARP packet
                logging.info("[OS Deception] Processing ARP Packet...")
                try:
                    req = self.unpack_arp_packet(raw_pkt)
                    rsp = self.deceived_pkt_synthesis("arp", req, template_dict)
                    if rsp:
                        self.conn.sock.send(rsp)
                        logging.info("[OS Deception] Sent deceptive ARP response.")
                except Exception as e:
                    logging.error(f"[OS Deception] Error processing ARP: {e}")

            elif eth_protocol == 8:  # IP packet
                ip_header = raw_pkt[ETH_HEADER_LEN:ETH_HEADER_LEN + IP_HEADER_LEN]
                _, _, _, _, _, _, protocol, _, _, _ = struct.unpack("!BBHHHBBH4s4s", ip_header)

                proc_map = {1: "icmp", 6: "tcp", 17: "udp"}
                proc = proc_map.get(protocol, None)

                if proc:
                    logging.info(f"[OS Deception] Processing {proc.upper()} packet...")
                    try:
                        pkt.unpack()  # Ensure Packet class has this method
                        rsp = self.deceived_pkt_synthesis(proc, pkt, template_dict)
                        if rsp:
                            self.conn.sock.send(rsp)
                            logging.info(f"[OS Deception] Sent deceptive {proc.upper()} response.")
                    except Exception as e:
                        logging.error(f"[OS Deception] Error processing {proc.upper()} packet: {e}")
                else:
                    logging.warning(f"[OS Deception] Unknown protocol: {protocol}, skipping.")

    def unpack_arp_packet(self, packet):
        """ Unpack ARP packet manually """
        arp_header = packet[ETH_HEADER_LEN:ETH_HEADER_LEN + ARP_HEADER_LEN]
        hw_type, proto_type, hw_size, proto_size, opcode, sender_mac, sender_ip, recv_mac, recv_ip = struct.unpack(
            '!2s2s1s1s2s6s4s6s4s', arp_header)

        return {
            "hw_type": hw_type, "proto_type": proto_type, "hw_size": hw_size, "proto_size": proto_size,
            "opcode": opcode, "sender_mac": sender_mac, "sender_ip": sender_ip, "recv_mac": recv_mac, "recv_ip": recv_ip
        }

    def load_file(self, pkt_type: str):
        """ Load OS fingerprinting response records """
        file_path = os.path.join(self.os_record_path, f"{pkt_type}_record.txt")

        if not os.path.exists(file_path):
            logging.warning(f"[OS Deception] Missing {pkt_type} fingerprint record. Skipping...")
            return {}

        with open(file_path, "r") as file:
            try:
                return eval(file.readline())
            except Exception as e:
                logging.error(f"[OS Deception] Error loading {pkt_type} record: {e}")
                return {}

    def deceived_pkt_synthesis(self, proc: str, req, template: dict):
        """ Generates a deceptive response packet based on stored fingerprints """
        try:
            key, _ = gen_key(proc, req)
            raw_template = template[proc].get(key, None)
            if not raw_template:
                logging.warning(f"[OS Deception] No deception template found for {proc}.")
                return None

            template_pkt = Packet(raw_template)
            template_pkt.unpack()

            if proc == "arp":
                template_pkt.l3_field["sender_mac"] = settings.mac
                template_pkt.l3_field["sender_ip"] = socket.inet_aton(self.host)
                template_pkt.l3_field["recv_mac"] = req["sender_mac"]
                template_pkt.l3_field["recv_ip"] = req["sender_ip"]

            template_pkt.pack()
            return template_pkt.packet
        except Exception as e:
            logging.error(f"[OS Deception] Error in packet synthesis: {e}")
            return None

def gen_key(proc, packet):
    """ Generates a key for identifying fingerprint packets """
    if proc == "tcp":
        return gen_tcp_key(packet)
    elif proc == "udp":
        return gen_udp_key(packet)
    elif proc == "icmp":
        return gen_icmp_key(packet)
    elif proc == "arp":
        return gen_arp_key(packet)
    else:
        return None, None
