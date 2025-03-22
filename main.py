# === Final main.py ===

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
import ast
from collections import defaultdict

import src.settings as settings
from src.port_deceiver import PortDeceiver
from src.os_deceiver import OsDeceiver, gen_key

# Logging setup
logging.basicConfig(
    format='%(asctime)s [%(levelname)s]: %(message)s',
    datefmt='%y-%m-%d %H:%M',
    level=logging.DEBUG
)

DEFAULT_OS_RECORD_PATH = settings.OS_RECORD_PATH


def ensure_directory_exists(directory):
    os.makedirs(directory, exist_ok=True)
    logging.info(f"Ensured directory exists: {directory}")


def ensure_file_permissions(file_path):
    if os.path.exists(file_path):
        os.chmod(file_path, 0o644)
        logging.info(f"Set correct permissions for {file_path}")


def validate_nic(nic):
    if not os.path.exists(f"/sys/class/net/{nic}"):
        logging.error(f"Network interface {nic} not found!")
        sys.exit(1)


def set_promiscuous_mode(nic):
    try:
        subprocess.run(["sudo", "ip", "link", "set", nic, "promisc", "on"], check=True)
        logging.info(f"Promiscuous mode enabled for {nic}")
    except subprocess.CalledProcessError as e:
        logging.error(f"Failed to enable promiscuous mode on {nic}: {e}")
        sys.exit(1)


def collect_fingerprint(target_host, dest, nic):
    logging.info(f"Starting fingerprint collection on {target_host} via {nic}")
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
    except Exception as e:
        logging.error(f"Socket error on {nic}: {e}")
        sys.exit(1)

    timeout = time.time() + 180
    packet_count = 0

    while time.time() < timeout:
        try:
            packet, _ = sock.recvfrom(65565)
            eth_type = struct.unpack("!H", packet[12:14])[0]
            proto = None

            if eth_type == 0x0806:
                proto = "arp"
            elif eth_type == 0x0800:
                ip_proto = packet[23]
                if ip_proto == 1:
                    proto = "icmp"
                elif ip_proto == 6:
                    proto = "tcp"
                elif ip_proto == 17:
                    proto = "udp"

            if proto:
                with open(packet_files[proto], "ab") as f:
                    f.write(packet + b"\n")
                ensure_file_permissions(packet_files[proto])
                packet_count += 1
        except Exception as e:
            logging.error(f"Error capturing packet: {e}")
            break

    logging.info(f"Fingerprinting done. Captured {packet_count} packets.")


def convert_to_json(file_path):
    try:
        with open(file_path, "rb") as f:
            content = f.read().strip()

        if not content:
            logging.warning(f"Skipping empty file: {file_path}")
            return

        try:
            record_dict = ast.literal_eval(content.decode("latin1"))
        except Exception as e:
            logging.error(f"Could not parse legacy dict from {file_path}: {e}")
            return

        json_base64 = {
            base64.b64encode(k if isinstance(k, bytes) else k.encode("latin1")).decode():
            base64.b64encode(v if isinstance(v, bytes) else v.encode("latin1")).decode()
            for k, v in record_dict.items() if v
        }

        with open(file_path, "w") as f:
            json.dump(json_base64, f, indent=2)

        logging.info(f"Converted {file_path} to JSON.")

    except Exception as e:
        logging.error(f"Error converting {file_path} to JSON: {e}")
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(description="Camouflage Cloak - OS & Port Deception")
    parser.add_argument("--host", required=True, help="Target IP")
    parser.add_argument("--nic", required=True, help="Interface to capture/deceive")
    parser.add_argument("--scan", choices=["ts", "od", "pd"], required=True, help="Scan mode")
    parser.add_argument("--dest", default=DEFAULT_OS_RECORD_PATH, help="Fingerprint storage directory")
    parser.add_argument("--os", help="OS to mimic (for deception)")
    parser.add_argument("--te", type=int, help="Timeout (minutes) for deception")
    parser.add_argument("--status", help="Port status (for PD)")
    parser.add_argument("--mac", help="Override MAC address to use for spoofing")
    args = parser.parse_args()

    validate_nic(args.nic)
    if args.scan == 'ts':
        collect_fingerprint(args.host, args.dest, args.nic)

    elif args.scan == 'od':
        if not args.os or args.te is None:
            logging.error("--os and --te are required for OS deception")
            return

        record_dir = os.path.join(args.dest, args.os)
        ensure_directory_exists(record_dir)

        for proto in ["tcp", "udp", "icmp", "arp"]:
            file_path = os.path.join(record_dir, f"{proto}_record.txt")
            if os.path.exists(file_path):
                convert_to_json(file_path)
                ensure_file_permissions(file_path)

        deceiver = OsDeceiver(
            target_host=args.host,
            target_os=args.os,
            dest=record_dir,
            nic=args.nic,
            mac=args.mac
        )
        deceiver.os_deceive(args.te)

    elif args.scan == 'pd':
        if not args.status or args.te is None:
            logging.error("--status and --te are required for Port Deception")
            return

        deceiver = PortDeceiver(args.host)
        deceiver.deceive_ps_hs(args.status)


if __name__ == '__main__':
    main()
