import logging
import argparse
import os
import time
import socket
import struct
import threading
import sys
import subprocess
import src.settings as settings
from src.port_deceiver import PortDeceiver
from src.os_deceiver import OsDeceiver

# Configure logging
logging.basicConfig(
    format='%(asctime)s [%(levelname)s]: %(message)s',
    datefmt='%y-%m-%d %H:%M',
    level=logging.DEBUG  # Use DEBUG mode for live packet analysis
)

def validate_nic(nic):
    """Check if the network interface exists before use."""
    if not os.path.exists(f"/sys/class/net/{nic}"):
        logging.error(f"Network interface {nic} not found! Check your NIC name.")
        sys.exit(1)

def set_promiscuous_mode(nic):
    """Enable promiscuous mode securely."""
    try:
        subprocess.run(["sudo", "ip", "link", "set", nic, "promisc", "on"], check=True)
        logging.info("Promiscuous mode enabled successfully.")
    except subprocess.CalledProcessError as e:
        logging.error(f"Failed to set promiscuous mode: {e}")
        sys.exit(1)

def collect_fingerprint(target_host, dest, nic, max_packets=100):
    """
    Captures fingerprinting packets for the target host only, including responses to malicious scans.
    """
    logging.info(f"Starting OS Fingerprinting on {target_host} (Max: {max_packets} packets)")

    os.makedirs(dest, exist_ok=True)
    
    packet_files = {
        "arp": os.path.abspath(os.path.join(dest, "arp_record.txt")),
        "icmp": os.path.abspath(os.path.join(dest, "icmp_record.txt")),
        "tcp": os.path.abspath(os.path.join(dest, "tcp_record.txt")),
        "udp": os.path.abspath(os.path.join(dest, "udp_record.txt")),
    }
    
    validate_nic(nic)
    set_promiscuous_mode(nic)
    
    time.sleep(2)  # Allow NIC to enter promiscuous mode

    try:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
        sock.bind((nic, 0))
    except PermissionError:
        logging.error("Root privileges required to open raw sockets. Run the script with sudo.")
        sys.exit(1)
    except Exception as e:
        logging.error(f"Error opening raw socket: {e}")
        sys.exit(1)

    packet_count = 0
    logging.info(f"Storing fingerprint data in: {dest}")

    timeout = time.time() + 300  # 5 minutes
    while time.time() < timeout:
        try:
            packet, _ = sock.recvfrom(65565)
            eth_protocol = struct.unpack("!H", packet[12:14])[0]
            proto_type = None
            packet_data = None

            logging.debug(f"Captured raw packet ({len(packet)} bytes): {packet.hex()[:100]}")

            if eth_protocol == 0x0806:
                proto_type = "arp"
                packet_data = f"ARP Packet: Raw={packet.hex()[:50]}\n"
                logging.info("Captured ARP Packet (Possible Malicious Scan)")
            elif eth_protocol == 0x0800:
                ip_proto = packet[23]
                if ip_proto == 1:
                    proto_type = "icmp"
                    icmp_header = packet[34:42]
                    icmp_type, icmp_code, icmp_checksum = struct.unpack("!BBH", icmp_header[:4])
                    packet_data = f"ICMP Packet: Type={icmp_type}, Code={icmp_code}, Raw={packet.hex()[:50]}\n"
                elif ip_proto == 6:
                    proto_type = "tcp"
                    tcp_header = struct.unpack("!HHLLBBHHH", packet[34:54])
                    src_port, dst_port, seq, ack, offset_reserved_flags, flags, window, checksum, urg_ptr = tcp_header
                    packet_data = f"TCP Packet: SrcPort={src_port}, DstPort={dst_port}, Flags={flags}, Raw={packet.hex()[:50]}\n"
                elif ip_proto == 17:
                    proto_type = "udp"
                    udp_header = struct.unpack("!HHHH", packet[34:42])
                    src_port, dst_port, length, checksum = udp_header
                    packet_data = f"UDP Packet: SrcPort={src_port}, DstPort={dst_port}, Raw={packet.hex()[:50]}\n"
                
            if proto_type and packet_data:
                with open(packet_files[proto_type], "a") as f:
                    f.write(packet_data)
                packet_count += 1

        except Exception as e:
            logging.error(f"Error while receiving packets: {e}")
            break

    logging.info(f"OS Fingerprinting Completed. Captured {packet_count} packets.")

def main():
    parser = argparse.ArgumentParser(description="Camouflage Cloak - OS Deception & Fingerprinting System")
    parser.add_argument("--host", required=True, help="Target host IP to deceive or fingerprint")
    parser.add_argument("--nic", required=True, help="Network interface to capture packets")
    parser.add_argument("--scan", choices=["ts", "od", "pd"], help="Scanning technique for fingerprint collection")
    parser.add_argument("--dest", help="Directory to store OS fingerprints (Required for --scan ts)")
    parser.add_argument("--os", help="OS to mimic (Required for --od)")
    parser.add_argument("--te", type=int, help="Timeout duration in minutes (Required for --od and --pd)")
    parser.add_argument("--status", help="Port status (Required for --pd)")
    args = parser.parse_args()

    validate_nic(args.nic)

    if args.scan == 'ts':
        if not args.dest:
            logging.error("Missing required argument: --dest for --scan ts")
            return
        collect_fingerprint(args.host, args.dest, args.nic)
    elif args.scan == 'od':
        if not args.os or not args.te:
            logging.error("Missing required arguments: --os and --te are required for --od")
            return
        deceiver = OsDeceiver(args.host, args.os)
        deceiver.os_deceive()
        threading.Timer(args.te * 60, deceiver.stop).start()
    elif args.scan == 'pd':
        if not args.status or not args.te:
            logging.error("Missing required arguments: --status and --te are required for --pd")
            return
        deceiver = PortDeceiver(args.host)
        deceiver.deceive_ps_hs(args.status)
        threading.Timer(args.te * 60, deceiver.stop).start()
    else:
        logging.error("Invalid command. Specify --scan ts, --scan od, or --scan pd.")

if __name__ == '__main__':
    main()
