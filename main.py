# --- main.py ---

import os
import sys
import time
import json
import socket
import logging
import argparse
import subprocess
from collections import defaultdict
from scapy.all import sniff, wrpcap, get_if_hwaddr

# Setup paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SRC_DIR = os.path.join(BASE_DIR, "src")
os.makedirs(SRC_DIR, exist_ok=True)
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)

# Logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

try:
    import settings
    from Packet import Packet
    from os_deceiver import OsDeceiver
    from port_deceiver import PortDeceiver
    from fingerprint_gen import generateKey
    from os_recorder import templateSynthesis
    from ja3_extractor import extract_ja3, match_ja3_rule
except ImportError as e:
    logging.error(f"[ERROR]: Import error: {e}")
    sys.exit(1)

def ensure_dir(path):
    try:
        os.makedirs(path, exist_ok=True)
    except Exception as e:
        logging.error(f"[ERROR]: Cannot create directory {path}: {e}")
        sys.exit(1)

def validate_nic(nic):
    path = f"/sys/class/net/{nic}"
    if not os.path.exists(path):
        logging.error(f"[ERROR]: NIC {nic} not found")
        sys.exit(1)
    try:
        mac = get_if_hwaddr(nic)
        logging.info(f"✅ NIC {nic} MAC: {mac}")
    except Exception as e:
        logging.warning(f"[WARN]: MAC lookup failed for {nic}: {e}")

def set_promisc(nic):
    try:
        subprocess.run(["ip", "link", "set", nic, "promisc", "on"], check=True)
        logging.info(f"🔁 Enabled promiscuous mode on {nic}")
    except subprocess.CalledProcessError as e:
        logging.warning(f"[WARN]: Promiscuous mode failed: {e}")

def get_host_ip(nic):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"

def run_template_learning(host_ip, dest_path, nic, enable_dns=False, enable_ja3=False):
    template_dict = defaultdict(dict)
    pair_dict = {}

    def handle(pkt):
        try:
            packet = Packet(bytes(pkt))
            packet.interface = nic
            packet.unpack()
            proto = packet.l4 if packet.l4 else packet.l3
            templateSynthesis(packet, proto.upper(), template_dict, pair_dict, host_ip)
        except Exception as e:
            logging.debug(f"[SKIP]: Failed to unpack packet: {e}")

    logging.info(f"📡 Listening for templates on {nic} (300s)...")
    validate_nic(nic)
    set_promisc(nic)
    time.sleep(1)
    sniff(iface=nic, timeout=300, prn=handle, store=False)

    for proto in template_dict:
        outfile = os.path.join(dest_path, f"{proto.lower()}_record.txt")
        outdata = {
            key.hex(): value.hex()
            for key, value in template_dict[proto].items() if value
        }
        with open(outfile, "w") as f:
            json.dump(outdata, f, indent=2)
        logging.info(f"📦 Saved {proto} templates: {outfile}")

def main():
    parser = argparse.ArgumentParser(description="🛡️ Camouflage Cloak Deception Engine")
    parser.add_argument("--scan", choices=["ts", "od", "pd"], required=True)
    parser.add_argument("--host", required=False)
    parser.add_argument("--nic", required=False)
    parser.add_argument("--dest", required=False)
    parser.add_argument("--os", required=False)
    parser.add_argument("--status", required=False)
    parser.add_argument("--te", type=int, default=5)
    parser.add_argument("--replay", action="store_true")
    parser.add_argument("--interactive", action="store_true")
    parser.add_argument("--dns", action="store_true")
    parser.add_argument("--ja3", action="store_true")
    args = parser.parse_args()

    if not args.nic:
        args.nic = settings.NIC_PROBE
        logging.info(f"[INFO]: Default NIC set to {args.nic}")

    if not args.host:
        args.host = get_host_ip(args.nic)
        logging.info(f"[INFO]: Auto-detected IP: {args.host}")

    validate_nic(args.nic)
    mac = get_if_hwaddr(args.nic)

    if args.scan == "ts":
        dest = os.path.abspath(args.dest or settings.OS_RECORD_PATH)
        ensure_dir(dest)
        run_template_learning(args.host, dest, args.nic, enable_dns=args.dns, enable_ja3=args.ja3)

    elif args.scan == "od":
        if not args.os:
            logging.error("[ERROR]: --os is required for os deception mode")
            return
        record_path = os.path.join(settings.OS_RECORD_PATH, args.os.lower())
        deceiver = OsDeceiver(
            target_host=args.host,
            target_os=args.os,
            dest=record_path,
            nic=args.nic,
            replay=args.replay,
            interactive=args.interactive,
            enable_dns=args.dns,
            enable_ja3=args.ja3
        )
        deceiver.os_deceive(timeout_minutes=args.te)

    elif args.scan == "pd":
        if not args.status:
            logging.error("[ERROR]: --status required for port deception mode")
            return
        try:
            port_map = json.loads(args.status)
        except Exception as e:
            logging.error(f"[ERROR]: Invalid --status: {e}")
            return
        deceiver = PortDeceiver(
            interface_ip=args.host,
            os_name=args.os,
            ports_config=port_map,
            nic=args.nic,
            mac=mac,
            replay=args.replay,
            interactive=args.interactive
        )
        deceiver.run()

if __name__ == "__main__":
    main()
