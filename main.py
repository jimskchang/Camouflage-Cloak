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

# Define default OS fingerprint storage directory
BASE_DIR = "/home/user/Camouflage-Cloak/os_record"

def validate_nic(nic):
    """Check if the network interface exists before use."""
    if not os.path.exists(f"/sys/class/net/{nic}"):
        logging.error(f"❌ Network interface {nic} not found! Check your NIC name.")
        sys.exit(1)

def set_promiscuous_mode(nic):
    """Enable promiscuous mode securely using subprocess."""
    try:
        subprocess.run(["sudo", "ip", "link", "set", nic, "promisc", "on"], check=True)
        logging.info("✅ Promiscuous mode enabled successfully.")
    except subprocess.CalledProcessError as e:
        logging.error(f"❌ Failed to set promiscuous mode: {e}")
        sys.exit(1)

def ensure_directory_exists(directory):
    """Ensure that the specified directory exists and has correct permissions."""
    try:
        os.makedirs(directory, exist_ok=True)
        os.chmod(directory, 0o755)  # Ensure read/write permissions
    except Exception as e:
        logging.error(f"❌ Error creating directory {directory}: {e}")

def collect_fingerprint(target_host, dest, nic, max_packets=100):
    """
    Captures fingerprinting packets for the target host only, including responses to malicious scans.
    """
    logging.info(f"📌 Starting OS Fingerprinting on {target_host} (Max: {max_packets} packets)")

    if not dest:
        dest = BASE_DIR  # Use default fingerprint directory if not provided
    ensure_directory_exists(dest)

    # Define paths for fingerprint files
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
        logging.error("❌ Root privileges required to open raw sockets. Run the script with sudo.")
        sys.exit(1)
    except Exception as e:
        logging.error(f"❌ Error opening raw socket: {e}")
        sys.exit(1)

    packet_count = 0
    logging.info(f"📌 Storing fingerprint data in: {dest}")

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
                logging.info("Captured ARP Packet (Possible Malicious Scan)")
            elif eth_protocol == 0x0800:
                ip_proto = packet[23]
                if ip_proto == 1:
                    proto_type = "icmp"
                    icmp_header = packet[34:42]
                    icmp_type, icmp_code, _ = struct.unpack("!BBH", icmp_header[:4])
                    packet_data = f"ICMP Packet: Type={icmp_type}, Code={icmp_code}, Raw={packet.hex()[:50]}\n"
                elif ip_proto == 6:
                    proto_type = "tcp"
                    tcp_header = struct.unpack("!HHLLBBHHH", packet[34:54])
                    src_port, dst_port, _, _, _, flags, _, _, _ = tcp_header
                    packet_data = f"TCP Packet: SrcPort={src_port}, DstPort={dst_port}, Flags={flags}, Raw={packet.hex()[:50]}\n"
                elif ip_proto == 17:
                    proto_type = "udp"
                    udp_header = struct.unpack("!HHHH", packet[34:42])
                    src_port, dst_port, _, _ = udp_header
                    packet_data = f"UDP Packet: SrcPort={src_port}, DstPort={dst_port}, Raw={packet.hex()[:50]}\n"

            if proto_type and packet_data:
                with open(packet_files[proto_type], "a", encoding="utf-8") as f:
                    f.write(packet_data)
                os.chmod(packet_files[proto_type], 0o644)  # Ensure files are readable
                packet_count += 1

        except Exception as e:
            logging.error(f"❌ Error while receiving packets: {e}")
            break

    logging.info(f"✅ OS Fingerprinting Completed. Captured {packet_count} packets.")

def main():
    parser = argparse.ArgumentParser(description="Camouflage Cloak - OS & Port Deception Against Malicious Scans")
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
            args.dest = BASE_DIR  # Set default directory if not specified
        ensure_directory_exists(args.dest)
        collect_fingerprint(args.host, args.dest, args.nic)
    elif args.scan == 'od':
        if not args.os or not args.te:
            logging.error("❌ Missing required arguments: --os and --te are required for --od")
            return
        if not args.dest:
            args.dest = f"{BASE_DIR}/{args.os}"
        ensure_directory_exists(args.dest)
        deceiver = OsDeceiver(args.host, args.os, args.dest)
        deceiver.os_deceive()
    elif args.scan == 'pd':
        if not args.status or not args.te:
            logging.error("❌ Missing required arguments: --status and --te are required for --pd")
            return
        deceiver = PortDeceiver(args.host)
        deceiver.deceive_ps_hs(args.status)
    else:
        logging.error("❌ Invalid command. Specify --scan ts, --scan od, or --scan pd.")

if __name__ == '__main__':
    main()
