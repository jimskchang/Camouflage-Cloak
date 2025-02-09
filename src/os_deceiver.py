import os
import logging
import socket
import struct
import time
import src.settings as settings
from src.Packet import Packet
from src.tcp import TcpConnect

class OsDeceiver:
    def __init__(self, target_host, target_os):
        """
        Initialize OS Deceiver for fingerprint collection & deception.
        """
        self.target_host_str = target_host
        self.target_host = socket.inet_aton(target_host)  # Convert IP to bytes
        self.target_os = target_os
        self.conn = TcpConnect(target_host)
        self.os_record_path = f"os_record/{self.target_os}"
        self.capture_timeout = 120  # Timeout for fingerprint capture (2 min)

        # Ensure OS record directory exists
        if not os.path.exists(self.os_record_path):
            logging.info(f"Creating OS record folder: {self.os_record_path}")
            os.makedirs(self.os_record_path)

        logging.info(f"OsDeceiver initialized for {self.target_host_str} (Mimic: {self.target_os})")

    def os_record(self, max_packets=100):
        """
        Captures OS fingerprinting packets (ARP, ICMP, TCP, UDP) and logs them.
        """
        logging.info(f"Capturing packets on {settings.NIC} for {self.target_host_str} (Max: {max_packets}, Timeout: {self.capture_timeout}s)")

        arp_pkt_dict = {}
        icmp_pkt_dict = {}
        tcp_pkt_dict = {}
        udp_pkt_dict = {}

        files = {
            "arp": os.path.join(self.os_record_path, "arp_record.txt"),
            "icmp": os.path.join(self.os_record_path, "icmp_record.txt"),
            "tcp": os.path.join(self.os_record_path, "tcp_record.txt"),
            "udp": os.path.join(self.os_record_path, "udp_record.txt")
        }

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

                logging.debug(f"Packet: Src={socket.inet_ntoa(src_IP)}, Dest={socket.inet_ntoa(dest_IP)}, Protocol={PROTOCOL}")

                # Ensure packet is meant for target host
                if dest_IP != self.target_host:
                    continue

                # **ICMP Packets**
                if PROTOCOL == 1:
                    key, _ = self.gen_icmp_key(packet)
                    icmp_pkt_dict[key] = packet
                    packet_count += 1
                    logging.info(f"Captured ICMP Packet ({packet_count})")
                    self._write_packet_to_file(files["icmp"], icmp_pkt_dict)

                # **TCP Packets**
                elif PROTOCOL == 6:
                    key, _ = self.gen_tcp_key(packet)
                    tcp_pkt_dict[key] = packet
                    packet_count += 1
                    logging.info(f"Captured TCP Packet ({packet_count})")
                    self._write_packet_to_file(files["tcp"], tcp_pkt_dict)

                # **UDP Packets**
                elif PROTOCOL == 17:
                    key, _ = self.gen_udp_key(packet)
                    udp_pkt_dict[key] = packet
                    packet_count += 1
                    logging.info(f"Captured UDP Packet ({packet_count})")
                    self._write_packet_to_file(files["udp"], udp_pkt_dict)

                # **ARP Packets**
                elif eth_protocol == 1544:
                    key, _ = self.gen_arp_key(packet)
                    arp_pkt_dict[key] = packet
                    packet_count += 1
                    logging.info(f"Captured ARP Packet ({packet_count})")
                    self._write_packet_to_file(files["arp"], arp_pkt_dict)

            if packet_count == 0:
                logging.warning("No packets captured! Check network interface settings and traffic.")

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

    def _write_packet_to_file(self, file_path, packet_dict):
        """Writes captured packets to the appropriate file."""
        try:
            with open(file_path, "w") as f:
                f.write(str(packet_dict))
        except Exception as e:
            logging.error(f"Error writing to file {file_path}: {e}")

    def gen_icmp_key(self, packet):
        """Generate ICMP fingerprinting key."""
        ip_header = packet[settings.ETH_HEADER_LEN: settings.ETH_HEADER_LEN + settings.IP_HEADER_LEN]
        icmp_header = packet[settings.ETH_HEADER_LEN + settings.IP_HEADER_LEN: settings.ETH_HEADER_LEN + settings.IP_HEADER_LEN + settings.ICMP_HEADER_LEN]
        key = ip_header[12:16] + icmp_header[:4]
        return key, packet

    def gen_tcp_key(self, packet):
        """Generate TCP fingerprinting key."""
        ip_header = packet[settings.ETH_HEADER_LEN: settings.ETH_HEADER_LEN + settings.IP_HEADER_LEN]
        tcp_header = packet[settings.ETH_HEADER_LEN + settings.IP_HEADER_LEN: settings.ETH_HEADER_LEN + settings.IP_HEADER_LEN + settings.TCP_HEADER_LEN]
        key = ip_header[12:16] + tcp_header[:4]
        return key, packet

    def gen_udp_key(self, packet):
        """Generate UDP fingerprinting key."""
        ip_header = packet[settings.ETH_HEADER_LEN: settings.ETH_HEADER_LEN + settings.IP_HEADER_LEN]
        udp_header = packet[settings.ETH_HEADER_LEN + settings.IP_HEADER_LEN: settings.ETH_HEADER_LEN + settings.IP_HEADER_LEN + 8]
        key = ip_header[12:16] + udp_header[:4]
        return key, packet

    def gen_arp_key(self, packet):
        """Generate ARP fingerprinting key."""
        arp_header = packet[settings.ETH_HEADER_LEN: settings.ETH_HEADER_LEN + settings.ARP_HEADER_LEN]
        key = arp_header[:8]
        return key, packet
