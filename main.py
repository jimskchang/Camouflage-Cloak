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

import src.settings as settings
from src.port_deceiver import PortDeceiver
from src.os_deceiver import OsDeceiver
from src.settings import MAC

# Logging setup
logging.basicConfig(
    format='%(asctime)s [%(levelname)s]: %(message)s',
    datefmt='%y-%m-%d %H:%M:%S',
    level=logging.INFO
)

def ensure_directory_exists(directory: str):
    try:
        os.makedirs(directory, exist_ok=True)
        logging.info(f"📁 Ensured directory exists: {directory}")
    except Exception as e:
        logging.error(f"❌ Failed to create directory {directory}: {e}")
        sys.exit(1)

def ensure_file_permissions(file_path: str):
    try:
        if os.path.exists(file_path):
            os.chmod(file_path, 0o644)
            logging.info(f"🔐 Set permissions for {file_path}")
    except Exception as e:
        logging.error(f"❌ Failed to set permissions for {file_path}: {e}")

def validate_nic(nic: str):
    path = f"/sys/class/net/{nic}"
    if not os.path.exists(path):
        logging.error(f"❌ Network interface {nic} not found.")
        sys.exit(1)
    try:
        with open(f"{path}/address", "r") as f:
            mac = f.read().strip()
            logging.info(f"✅ NIC {nic} MAC address: {mac}")
    except Exception as e:
        logging.warning(f"⚠ Could not read MAC address for NIC {nic}: {e}")

def set_promiscuous_mode(nic: str):
    try:
        subprocess.run(["ip", "link", "set", nic, "promisc", "on"], check=True)
        logging.info(f"🔁 Promiscuous mode enabled for {nic}")
    except subprocess.CalledProcessError as e:
        logging.error(f"❌ Failed to set promiscuous mode: {e}")
        sys.exit(1)

def collect_fingerprint(target_host, dest, nic):
    logging.info(f"📡 Starting OS fingerprint collection on {target_host} via {nic}")

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
        logging.error("❌ Root privileges required for raw socket.")
        sys.exit(1)
    except Exception as e:
        logging.error(f"❌ Failed to bind socket: {e}")
        sys.exit(1)

    timeout = time.time() + 180
    packet_count = 0

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
            logging.error(f"❌ Error receiving packet: {e}")
            break

    logging.info(f"✅ Captured {packet_count} packets for fingerprinting.")

def convert_to_json(file_path: str):
    try:
        with open(file_path, "rb") as f:
            content = f.read().strip()
        if not content:
            logging.warning(f"⚠ Skipping empty file: {file_path}")
            return

        try:
            record_dict = ast.literal_eval(content.decode("latin1"))
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

        logging.info(f"✅ Converted {file_path} to base64 JSON.")

    except Exception as e:
        logging.error(f"❌ Error converting {file_path} to JSON: {e}")

def main():
    parser = argparse.ArgumentParser(description="🛡️ Camouflage Cloak: OS & Port Deception Engine")
    parser.add_argument("--host", required=True, help="Target IP to impersonate")
    parser.add_argument("--nic", required=True, help="Network interface to bind")
    parser.add_argument("--scan", choices=["ts", "od", "pd"], required=True, help="Scan mode: ts (template), od (os deceive), pd (port deceive)")
    parser.add_argument("--os", help="OS template to mimic (e.g., win10)")
    parser.add_argument("--te", type=int, help="Timeout in minutes for deception")
    parser.add_argument("--status", help="For --scan pd: open or close")
    parser.add_argument("--dest", help="Optional: path to OS fingerprint folder")

    args = parser.parse_args()
    validate_nic(args.nic)

    if args.scan == 'ts':
        dest = args.dest or settings.OS_RECORD_PATH
        collect_fingerprint(args.host, dest, args.nic)

    elif args.scan == 'od':
        if not args.os or args.te is None:
            logging.error("❌ Missing --os or --te for OS deception")
            return

        os_record_path = os.path.join(settings.OS_RECORD_PATH, args.os)
        ensure_directory_exists(os_record_path)

        # ✅ Convert legacy records to JSON-safe format
        for fname in ["arp_record.txt", "tcp_record.txt", "udp_record.txt", "icmp_record.txt"]:
            fpath = os.path.join(os_record_path, fname)
            convert_to_json(fpath)

        deceiver = OsDeceiver(
            target_host=args.host,
            target_os=args.os,
            dest=os_record_path,
            nic=args.nic
        )
        deceiver.os_deceive(timeout_minutes=args.te)

    elif args.scan == 'pd':
        if not args.status or args.te is None:
            logging.error("❌ Missing --status or --te for Port Deception")
            return
        deceiver = PortDeceiver(args.host, nic=args.nic)
        deceiver.deceive_ps_hs(args.status)

if __name__ == '__main__':
    main()
