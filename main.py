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

# 🔹 Ensure the OS fingerprint directory exists
def ensure_directory_exists(directory):
    """Ensure the directory exists, create if not."""
    try:
        os.makedirs(directory, exist_ok=True)
        logging.info(f"Ensured directory exists: {directory}")
    except Exception as e:
        logging.error(f"Failed to create directory {directory}: {e}")
        sys.exit(1)

# 🔹 Ensure OS fingerprint files are not locked
def ensure_file_permissions(file_path):
    """Ensure that the file has read and write permissions for all users."""
    try:
        os.chmod(file_path, 0o644)  # Read & Write for owner, Read for others
        logging.info(f"Set correct permissions for {file_path}")
    except Exception as e:
        logging.error(f"Failed to set permissions for {file_path}: {e}")

def validate_nic(nic):
    """Check if the network interface exists before use."""
    if not os.path.exists(f"/sys/class/net/{nic}"):
        logging.error(f"Network interface {nic} not found! Check your NIC name.")
        sys.exit(1)

def set_promiscuous_mode(nic):
    """Enable promiscuous mode securely using subprocess."""
    try:
        subprocess.run(["sudo", "ip", "link", "set", nic, "promisc", "on"], check=True)
        logging.info(f"Promiscuous mode enabled for {nic}")
    except subprocess.CalledProcessError as e:
        logging.error(f"Failed to set promiscuous mode: {e}")
        sys.exit(1)

def collect_fingerprint(target_host, dest, nic):
    """
    Captures fingerprinting packets for the target host only, including responses to malicious scans.
    Ensures that captured files are readable for later OS deception.
    """
    logging.info(f"Starting OS Fingerprinting on {target_host}")

    # Default fingerprint storage directory
    if not dest:
        dest = os.path.expanduser("~/Camouflage-Cloak/os_record")
    ensure_directory_exists(dest)

    packet_files = {
        "arp": os.path.join(dest, "arp_record.txt"),
        "icmp": os.path.join(dest, "icmp_record.txt"),
        "tcp": os.path.join(dest, "tcp_record.txt"),
        "udp": os.path.join(dest, "udp_record.txt"),
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

    timeout = time.time() + 180  # 3 minutes timeout
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
            elif eth_protocol == 0x0800:
                ip_proto = packet[23]
                if ip_proto == 1:
                    proto_type = "icmp"
                    packet_data = f"ICMP Packet: Raw={packet.hex()[:50]}\n"
                elif ip_proto == 6:
                    proto_type = "tcp"
                    packet_data = f"TCP Packet: Raw={packet.hex()[:50]}\n"
                elif ip_proto == 17:
                    proto_type = "udp"
                    packet_data = f"UDP Packet: Raw={packet.hex()[:50]}\n"

            if proto_type and packet_data:
                file_path = packet_files[proto_type]
                with open(file_path, "a") as f:
                    f.write(packet_data)

                # 🔹 **Ensure file is not locked**
                ensure_file_permissions(file_path)

                packet_count += 1

        except Exception as e:
            logging.error(f"Error while receiving packets: {e}")
            break

    logging.info(f"OS Fingerprinting Completed. Captured {packet_count} packets.")

def main():
    parser = argparse.ArgumentParser(description="Camouflage Cloak - OS & Port Deception Against Malicious Scans")
    parser.add_argument("--host", required=True, help="Target host IP to deceive or fingerprint")
    parser.add_argument("--nic", required=True, help="Network interface to capture packets")
    parser.add_argument("--scan", choices=["ts", "od", "pd"], required=True, help="Scanning technique for fingerprint collection")
    parser.add_argument("--dest", help="Directory to store OS fingerprints (Default: ~/Camouflage-Cloak/os_record)")
    parser.add_argument("--os", help="OS to mimic (Required for --od)")
    parser.add_argument("--te", type=int, help="Timeout duration in minutes (Required for --od and --pd)")
    parser.add_argument("--status", help="Port status (Required for --pd)")
    args = parser.parse_args()

    validate_nic(args.nic)

    if args.scan == 'ts':
        collect_fingerprint(args.host, args.dest, args.nic)
    elif args.scan == 'od':
        if not args.os or not args.te:
            logging.error("Missing required arguments: --os and --te are required for --od")
            return
        os_record_path = args.dest if args.dest else os.path.expanduser(f"~/Camouflage-Cloak/os_record/{args.os}")
        ensure_directory_exists(os_record_path)

        deceiver = OsDeceiver(args.host, args.os, os_record_path)
        deceiver.os_deceive()
    elif args.scan == 'pd':
        if not args.status or not args.te:
            logging.error("Missing required arguments: --status and --te are required for --pd")
            return
        deceiver = PortDeceiver(args.host)
        deceiver.deceive_ps_hs(args.status)
    else:
        logging.error("Invalid command. Specify --scan ts, --scan od, or --scan pd.")

if __name__ == '__main__':
    main()
