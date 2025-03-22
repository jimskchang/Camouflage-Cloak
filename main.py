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
from src.os_deceiver import OsDeceiver
from src.settings import MAC  # Use the correct MAC address

# Configure logging
logging.basicConfig(
    format='%(asctime)s [%(levelname)s]: %(message)s',
    datefmt='%y-%m-%d %H:%M',
    level=logging.DEBUG
)

# Use the consistent record path from settings
DEFAULT_OS_RECORD_PATH = settings.OS_RECORD_PATH

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
    logging.info(f"📡 Starting OS Fingerprinting on {target_host} via {nic}")
    dest = dest or DEFAULT_OS_RECORD_PATH
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
    timeout = time.time() + 180
    logging.info(f"📥 Capturing packets to: {dest}")

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

    logging.info(f"✅ Fingerprinting complete. Captured {packet_count} packets.")

def convert_to_json(file_path):
    """
    Converts legacy fingerprint str(dict) files to base64-encoded JSON format.
    Handles binary content (e.g., null bytes).
    """
    try:
        with open(file_path, "rb") as f:
            raw_bytes = f.read()

        if not raw_bytes:
            logging.warning(f"⚠ Skipping empty file: {file_path}")
            return

        try:
            record_dict = ast.literal_eval(raw_bytes.decode("latin1"))
        except Exception as e:
            logging.error(f"❌ Could not parse legacy dict from {file_path}: {e}")
            return

        json_base64 = {}
        for k, v in record_dict.items():
            if v is None:
                continue
            key_b64 = base64.b64encode(k if isinstance(k, bytes) else k.encode("latin1")).decode("utf-8")
            val_b64 = base64.b64encode(v if isinstance(v, bytes) else v.encode("latin1")).decode("utf-8")
            json_base64[key_b64] = val_b64

        with open(file_path, "w") as f:
            json.dump(json_base64, f, indent=2)

        logging.info(f"✅ Converted {file_path} to base64-encoded JSON format.")

    except Exception as e:
        logging.error(f"❌ Error converting {file_path} to JSON: {e}")
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(description="Camouflage Cloak - OS & Port Deception")
    parser.add_argument("--host", required=True, help="Target IP")
    parser.add_argument("--nic", required=True, help="Network interface to use (usually NIC_TARGET)")
    parser.add_argument("--scan", choices=["ts", "od", "pd"], required=True, help="Scan mode")
    parser.add_argument("--dest", default=DEFAULT_OS_RECORD_PATH, help="Path to store or load OS fingerprint records")
    parser.add_argument("--os", help="OS to mimic (used with --od)")
    parser.add_argument("--te", type=int, help="Timeout duration in minutes")
    parser.add_argument("--status", help="Port status to fake (used with --pd)")
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

        for proto in ["arp", "tcp", "udp", "icmp"]:
            file_path = os.path.join(os_record_path, f"{proto}_record.txt")
            ensure_file_permissions(file_path)
            convert_to_json(file_path)

        deceiver = OsDeceiver(args.host, args.os, os_record_path)
        deceiver.os_deceive(args.te)

    elif args.scan == 'pd':
        if not args.status or args.te is None:
            logging.error("Missing required arguments for Port Deception: --status and --te")
            return
        deceiver = PortDeceiver(args.host)
        deceiver.deceive_ps_hs(args.status)

if __name__ == '__main__':
    main()
