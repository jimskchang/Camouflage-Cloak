import logging
import argparse
import os
import time
import socket
import struct
import sys
import subprocess
import json
import base64
from collections import defaultdict

import src.settings as settings
from src.port_deceiver import PortDeceiver
from src.os_deceiver import OsDeceiver, gen_key

# Configure logging
logging.basicConfig(
    format='%(asctime)s [%(levelname)s]: %(message)s',
    datefmt='%y-%m-%d %H:%M',
    level=logging.DEBUG
)

DEFAULT_OS_RECORD_PATH = os.path.join(settings.PROJECT_PATH, "os_record")

def ensure_directory_exists(directory):
    try:
        os.makedirs(directory, exist_ok=True)
        logging.info(f"Ensured directory exists: {directory}")
    except Exception as e:
        logging.error(f"Failed to create directory {directory}: {e}")
        sys.exit(1)

def ensure_file_permissions(file_path):
    try:
        if os.path.exists(file_path):
            os.chmod(file_path, 0o644)
            logging.info(f"Set correct permissions for {file_path}")
    except Exception as e:
        logging.error(f"Failed to set permissions for {file_path}: {e}")

def validate_nic(nic):
    if not os.path.exists(f"/sys/class/net/{nic}"):
        logging.error(f"Network interface {nic} not found! Check your NIC name.")
        sys.exit(1)

def set_promiscuous_mode(nic):
    try:
        subprocess.run(["sudo", "ip", "link", "set", nic, "promisc", "on"], check=True)
        logging.info(f"Promiscuous mode enabled for {nic}")
    except subprocess.CalledProcessError as e:
        logging.error(f"Failed to set promiscuous mode: {e}")
        sys.exit(1)

def collect_fingerprint(target_host, dest, nic):
    logging.info(f"Starting OS Fingerprinting on {target_host}")
    if not dest or dest == settings.OS_RECORD_PATH:
        dest = DEFAULT_OS_RECORD_PATH

    ensure_directory_exists(dest)

    packet_files = {
        "arp": os.path.join(dest, "arp_record.txt"),
        "icmp": os.path.join(dest, "icmp_record.txt"),
        "tcp": os.path.join(dest, "tcp_record.txt"),
        "udp": os.path.join(dest, "udp_record.txt"),
    }

    validate_nic(nic)
    set_promiscuous_mode(nic)
    time.sleep(2)

    try:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
        sock.bind((nic, 0))
    except PermissionError:
        logging.error("Root privileges required to open raw sockets.")
        sys.exit(1)
    except Exception as e:
        logging.error(f"Error opening raw socket: {e}")
        sys.exit(1)

    packet_count = 0
    logging.info(f"Storing fingerprint data in: {dest}")
    timeout = time.time() + 180

    while time.time() < timeout:
        try:
            packet, _ = sock.recvfrom(65565)
            eth_protocol = struct.unpack("!H", packet[12:14])[0]
            proto_type = None

            if eth_protocol == 0x0806:
                proto_type = "arp"
            elif eth_protocol == 0x0800:
                ip_proto = packet[23]
                if ip_proto == 1:
                    proto_type = "icmp"
                elif ip_proto == 6:
                    proto_type = "tcp"
                elif ip_proto == 17:
                    proto_type = "udp"

            if proto_type:
                file_path = packet_files[proto_type]
                with open(file_path, "ab") as f:
                    f.write(packet + b"\n")
                ensure_file_permissions(file_path)
                packet_count += 1

        except Exception as e:
            logging.error(f"Error while receiving packets: {e}")
            break

    logging.info(f"OS Fingerprinting Completed. Captured {packet_count} packets.")

def regenerate_record_json(os_record_path):
    raw_records = defaultdict(dict)
    for proto in ["tcp", "udp", "icmp", "arp"]:
        file_path = os.path.join(os_record_path, f"{proto}_record.txt")
        if not os.path.exists(file_path):
            continue

        try:
            with open(file_path, "rb") as f:
                lines = f.read().split(b"\n")

            for pkt in lines:
                if not pkt.strip():
                    continue
                key, _ = gen_key(proto, pkt)
                raw_records[proto][key] = pkt

            with open(file_path, "w") as f:
                encoded = {
                    base64.b64encode(k).decode(): base64.b64encode(v).decode()
                    for k, v in raw_records[proto].items()
                }
                json.dump(encoded, f, indent=2)

            print(f"✅ Regenerated and converted {proto}_record.txt")
        except Exception as e:
            print(f"❌ Error processing {proto}_record.txt: {e}")

def main():
    parser = argparse.ArgumentParser(description="Camouflage Cloak - OS & Port Deception")
    parser.add_argument("--host", required=True, help="Target IP")
    parser.add_argument("--nic", required=True, help="Network interface")
    parser.add_argument("--scan", choices=["ts", "od", "pd"], required=True, help="Scan mode")
    parser.add_argument("--dest", default=DEFAULT_OS_RECORD_PATH, help="OS fingerprint save dir")
    parser.add_argument("--os", help="OS to mimic for deception (for --od)")
    parser.add_argument("--te", type=int, help="Timeout in minutes (for --od or --pd)")
    parser.add_argument("--status", help="Port status (for --pd)")
    args = parser.parse_args()

    validate_nic(args.nic)

    if args.scan == 'ts':
        collect_fingerprint(args.host, args.dest, args.nic)

    elif args.scan == 'od':
        if not args.os or args.te is None:
            logging.error("Missing required arguments for OS Deception: --os and --te")
            return

        os_record_path = os.path.join(DEFAULT_OS_RECORD_PATH, args.os)
        ensure_directory_exists(os_record_path)

        regenerate_record_json(os_record_path)

        deceiver = OsDeceiver(
            target_host=args.host,
            target_os=args.os,
            dest=os_record_path,
            nic=args.nic
        )
        deceiver.os_deceive(timeout_minutes=args.te)

    elif args.scan == 'pd':
        if not args.status or args.te is None:
            logging.error("Missing required arguments for Port Deception: --status and --te")
            return
        deceiver = PortDeceiver(args.host)
        deceiver.deceive_ps_hs(args.status)

if __name__ == '__main__':
    main()
