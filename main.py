import logging
import argparse
import os
import time
import socket
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
        logging.error(f"❌ Network interface {nic} not found! Check your NIC name.")
        sys.exit(1)

def ensure_os_record_exists(dest: str = None) -> str:
    """Ensure os_record directory exists and return its path, but allow manual folder creation."""
    base_dir = os.path.expanduser("~/Camouflage-Cloak")
    os_record_path = os.path.join(base_dir, "os_record")

    if not os.path.exists(os_record_path):
        logging.info(f"⚠ os_record directory not found! Creating: {os_record_path}")
        try:
            os.makedirs(os_record_path, exist_ok=True)
            logging.info(f"✔ os_record directory created successfully.")
        except Exception as e:
            logging.error(f"❌ Failed to create os_record directory: {e}")
            sys.exit(1)

    if dest:
        dest_path = os.path.abspath(dest)
    else:
        dest_path = os_record_path  # Default to ~/Camouflage-Cloak/os_record/

    return dest_path

def validate_os_fingerprint_files(os_folder: str) -> None:
    """Ensure all required OS fingerprint files exist and are readable before running deception."""
    required_files = ["arp_record.txt", "tcp_record.txt", "udp_record.txt", "icmp_record.txt"]
    missing_files = []

    for filename in required_files:
        file_path = os.path.join(os_folder, filename)
        if not os.path.exists(file_path):
            missing_files.append(file_path)
    
    if missing_files:
        logging.error("❌ OS deception failed! Missing required files:")
        for f in missing_files:
            logging.error(f"  - {f} (Not Found)")
        logging.info("💡 Run --scan ts first to collect OS fingerprint data.")
        sys.exit(1)

def fix_file_permissions(directory: str) -> None:
    """Ensure that OS fingerprint files are always readable before OS deception."""
    try:
        if os.path.exists(directory):
            for root, _, files in os.walk(directory):
                for file in files:
                    file_path = os.path.join(root, file)
                    os.chmod(file_path, 0o644)  # Read & Write for owner, Read-only for others
                    logging.info(f"✔ Fixed permissions for {file_path} (Readable for --scan od)")
    except Exception as e:
        logging.error(f"❌ Failed to set file permissions: {e}")

def collect_fingerprint(target_host, dest, nic, max_packets=100):
    """
    Captures fingerprinting packets for the target host only, including responses to malicious scans.
    Runs for a fixed timeout of **3 minutes (180 seconds)**.
    """
    logging.info(f"🛠 Starting OS Fingerprinting on {target_host} (Max: {max_packets} packets, Timeout: 3 minutes)")

    os.makedirs(dest, exist_ok=True)
    
    packet_files = {
        "arp": os.path.abspath(os.path.join(dest, "arp_record.txt")),
        "icmp": os.path.abspath(os.path.join(dest, "icmp_record.txt")),
        "tcp": os.path.abspath(os.path.join(dest, "tcp_record.txt")),
        "udp": os.path.abspath(os.path.join(dest, "udp_record.txt")),
    }

    validate_nic(nic)

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
    logging.info(f"📂 Storing fingerprint data in: {dest}")

    timeout = time.time() + 180  # ⏳ **3-minute timeout restored**
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
                with open(packet_files[proto_type], "a") as f:
                    f.write(packet_data)
                packet_count += 1

        except Exception as e:
            logging.error(f"❌ Error while receiving packets: {e}")
            break

    logging.info(f"✅ OS Fingerprinting Completed. Captured {packet_count} packets.")

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
            logging.error("❌ Missing required arguments: --os and --te are required for --scan od")
            sys.exit(1)
        if not args.dest:
            logging.error("❌ Missing required argument: --dest is required for --scan od to load OS fingerprints")
            sys.exit(1)

        validate_os_fingerprint_files(args.dest)
        fix_file_permissions(args.dest)

        dest = os.path.abspath(args.dest)
        deceiver = OsDeceiver(args.host, args.os, dest)
        deceiver.os_deceive()

if __name__ == '__main__':
    main()
