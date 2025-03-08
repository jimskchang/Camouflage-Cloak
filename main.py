import logging
import argparse
import os
import time
import socket
import struct
import sys
import subprocess
import src.settings as settings
from src.port_deceiver import PortDeceiver
from src.os_deceiver import OsDeceiver

# Configure logging
logging.basicConfig(
    format='%(asctime)s [%(levelname)s]: %(message)s',
    datefmt='%y-%m-%d %H:%M',
    level=logging.DEBUG
)

def validate_nic(nic: str) -> None:
    """Check if the network interface exists before use."""
    if not os.path.exists(f"/sys/class/net/{nic}"):
        logging.error(f"Network interface {nic} not found! Check your NIC name.")
        sys.exit(1)

def ensure_os_record_exists(dest: str = None) -> str:
    """Ensure os_record directory exists and return its path."""
    if dest:
        dest_path = os.path.abspath(dest)
    else:
        base_dir = os.path.expanduser("~/Camouflage-Cloak")
        dest_path = os.path.join(base_dir, "os_record")

    if not os.path.exists(dest_path):
        logging.info(f"⚠ os_record directory not found! Creating: {dest_path}")
        try:
            os.makedirs(dest_path, exist_ok=True)
            logging.info(f"✔ os_record directory created successfully.")
        except Exception as e:
            logging.error(f"❌ Failed to create os_record directory: {e}")
            sys.exit(1)

    return dest_path

def collect_fingerprint(target_host: str, dest: str, nic: str) -> None:
    """Captures fingerprinting packets for the target host only."""
    logging.info(f"Starting OS Fingerprinting on {target_host}")

    dest = ensure_os_record_exists(dest)

    packet_files = {
        "arp": os.path.join(dest, "arp_record.txt"),
        "icmp": os.path.join(dest, "icmp_record.txt"),
        "tcp": os.path.join(dest, "tcp_record.txt"),
        "udp": os.path.join(dest, "udp_record.txt"),
    }

    validate_nic(nic)

    try:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
        sock.bind((nic, 0))
    except PermissionError:
        logging.error("Root privileges required to open raw sockets. Run the script with sudo.")
        sys.exit(1)
    except Exception as e:
        logging.error(f"Error opening raw socket: {e}")
        sys.exit(1)

    logging.info(f"Storing fingerprint data in: {dest}")
    timeout = time.time() + 300  # 5 minutes
    while time.time() < timeout:
        try:
            packet, _ = sock.recvfrom(65565)
            eth_protocol = struct.unpack("!H", packet[12:14])[0]
            proto_type = None
            packet_data = None

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
                with open(packet_files[proto_type], "a") as f:
                    f.write(packet_data)

        except Exception as e:
            logging.error(f"Error while receiving packets: {e}")
            break

    logging.info(f"OS Fingerprinting Completed.")

def main():
    parser = argparse.ArgumentParser(description="Camouflage Cloak - OS & Port Deception Against Malicious Scans")
    parser.add_argument("--host", required=True, help="Target host IP to deceive or fingerprint")
    parser.add_argument("--nic", required=True, help="Network interface to capture packets")
    parser.add_argument("--scan", choices=["ts", "od", "pd"], required=True, help="Scanning technique")
    parser.add_argument("--dest", help="Directory to store or load OS fingerprints")
    parser.add_argument("--os", help="OS to mimic (Required for --scan od)")
    parser.add_argument("--te", type=int, help="Timeout duration in minutes (Required for --scan od and --scan pd)")
    
    args = parser.parse_args()

    validate_nic(args.nic)

    if args.scan == 'ts':
        dest = ensure_os_record_exists(args.dest)
        collect_fingerprint(args.host, dest, args.nic)

    elif args.scan == 'od':
        if not args.os or not args.te:
            logging.error("Missing required arguments: --os and --te are required for --scan od")
            sys.exit(1)
        if not args.dest:
            logging.error("Missing required argument: --dest is required for --scan od to load OS fingerprints")
            sys.exit(1)
        dest = ensure_os_record_exists(args.dest)  # Load pre-stored fingerprints
        deceiver = OsDeceiver(args.host, args.os, dest)
        deceiver.os_deceive()

    elif args.scan == 'pd':
        if not args.te:
            logging.error("Missing required argument: --te is required for --scan pd")
            sys.exit(1)
        deceiver = PortDeceiver(args.host)
        deceiver.deceive_ps_hs(args.te)
    else:
        logging.error("Invalid command. Specify --scan ts, --scan od, or --scan pd.")

if __name__ == '__main__':
    main()
