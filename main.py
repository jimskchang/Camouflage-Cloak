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

def validate_nic(nic: str) -> None:
    """Check if the network interface exists before use."""
    if not os.path.exists(f"/sys/class/net/{nic}"):
        logging.error(f"Network interface {nic} not found! Check your NIC name.")
        sys.exit(1)

def set_promiscuous_mode(nic: str) -> None:
    """Enable promiscuous mode securely using subprocess."""
    try:
        subprocess.run(["sudo", "ip", "link", "set", nic, "promisc", "on"], check=True)
        logging.info("Promiscuous mode enabled successfully.")
    except subprocess.CalledProcessError as e:
        logging.error(f"Failed to set promiscuous mode: {e}")
        sys.exit(1)

def ensure_os_record_exists() -> str:
    """Manually ensure os_record/ directory exists inside /home/user/Camouflage-Cloak/"""
    base_dir = os.path.expanduser("~/Camouflage-Cloak")  # Use explicit home directory
    dest_path = os.path.join(base_dir, "os_record")

    if not os.path.exists(dest_path):
        logging.info(f"⚠ os_record directory not found! Creating manually at: {dest_path}")
        try:
            os.makedirs(dest_path, exist_ok=True)
            logging.info(f"✔ os_record directory created successfully.")
        except Exception as e:
            logging.error(f"❌ Failed to create os_record directory: {e}")
            sys.exit(1)
    
    return dest_path

def get_os_record_path(os_name: str) -> str:
    """Ensure the specific OS fingerprint directory exists under os_record."""
    base_path = ensure_os_record_exists()
    os_path = os.path.join(base_path, os_name)

    if not os.path.exists(os_path):
        logging.info(f"⚠ OS record directory for {os_name} not found! Creating manually at: {os_path}")
        try:
            os.makedirs(os_path, exist_ok=True)
            logging.info(f"✔ OS record directory created successfully.")
        except Exception as e:
            logging.error(f"❌ Failed to create OS record directory: {e}")
            sys.exit(1)
    
    return os_path

def collect_fingerprint(target_host: str, dest: str, nic: str, max_packets: int = 100) -> None:
    """Captures fingerprinting packets for the target host only, including responses to malicious scans."""
    logging.info(f"Starting OS Fingerprinting on {target_host} (Max: {max_packets} packets)")

    dest = ensure_os_record_exists()
    os.makedirs(dest, exist_ok=True)

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

    timeout = time.time() + 300  # 5 minutes timeout
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

            if proto_type and packet_data:
                with open(packet_files[proto_type], "a") as f:
                    f.write(packet_data)
                packet_count += 1

        except Exception as e:
            logging.error(f"Error while receiving packets: {e}")
            break

    logging.info(f"OS Fingerprinting Completed. Captured {packet_count} packets.")

def main():
    parser = argparse.ArgumentParser(description="Camouflage Cloak - OS & Port Deception Against Malicious Scans")
    parser.add_argument("--host", required=True, help="Target host IP to deceive or fingerprint")
    parser.add_argument("--nic", required=True, help="Network interface to capture packets")
    parser.add_argument("--scan", choices=["ts", "od", "pd"], help="Scanning technique for fingerprint collection")
    parser.add_argument("--os", help="OS to mimic (Required for --od)")
    parser.add_argument("--te", type=int, help="Timeout duration in minutes (Required for --od and --pd)")
    parser.add_argument("--status", help="Port status (Required for --pd)")
    args = parser.parse_args()

    validate_nic(args.nic)

    if args.scan == 'ts':
        collect_fingerprint(args.host, ensure_os_record_exists(), args.nic)
    elif args.scan == 'od':
        if not args.os or not args.te:
            logging.error("Missing required arguments: --os and --te are required for --od")
            return
        os_record_path = get_os_record_path(args.os)
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
