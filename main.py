import logging
import argparse
import os
import time
import sys
import subprocess
import json
import base64
import socket
from collections import defaultdict
from scapy.all import sniff, wrpcap, rdpcap

# --- Ensure src is in sys.path ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SRC_DIR = os.path.join(BASE_DIR, "src")
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)

# --- Initial Basic Logging ---
logging.basicConfig(
    format='%(asctime)s [%(levelname)s]: %(message)s',
    datefmt='%-y-%m-%d %H:%M:%S',
    level=logging.INFO
)

# --- Safe Imports ---
try:
    import src.settings as settings
    from src.port_deceiver import PortDeceiver
    from src.os_deceiver import OsDeceiver
    from src.fingerprint_utils import gen_key
    from src.os_recorder import templateSynthesis
    from src.Packet import Packet
    from src.settings import MAC, VLAN_MAP, GATEWAY_MAP, BASE_OS_TEMPLATES, get_mac_address
except ImportError as e:
    logging.error(f"\u274c Import Error: {e}")
    sys.exit(1)

# --- Cross-platform NIC detection ---
def get_interface_ip_map():
    ip_map = {}
    try:
        hostname = socket.gethostname()
        host_ips = socket.gethostbyname_ex(hostname)[2]
        for ip in host_ips:
            if not ip.startswith("127."):
                ip_map[f"interface_{len(ip_map)}"] = ip
    except Exception as e:
        logging.warning(f"\u26a0 NIC auto-detection failed: {e}")
    return ip_map

# --- Utility Functions ---
def ensure_directory_exists(directory: str):
    try:
        os.makedirs(directory, exist_ok=True)
        logging.info(f"\ud83d\udcc1 Ensured directory exists: {directory}")
    except Exception as e:
        logging.error(f"\u274c Failed to create directory {directory}: {e}")
        sys.exit(1)

def ensure_file_permissions(file_path: str):
    try:
        if os.path.exists(file_path):
            os.chmod(file_path, 0o644)
            logging.info(f"\ud83d\udd10 Set permissions for {file_path}")
    except Exception as e:
        logging.error(f"\u274c Failed to set permissions for {file_path}: {e}")

def validate_nic(nic: str):
    path = f"/sys/class/net/{nic}"
    if not os.path.exists(path):
        logging.error(f"\u274c Network interface {nic} not found.")
        sys.exit(1)
    try:
        with open(f"{path}/address", "r") as f:
            mac = f.read().strip()
            logging.info(f"\u2705 NIC {nic} MAC address: {mac}")
    except Exception as e:
        logging.warning(f"\u26a0 Could not read MAC address for NIC {nic}: {e}")

    vlan = VLAN_MAP.get(nic)
    gateway = GATEWAY_MAP.get(nic)
    if vlan:
        logging.info(f"\ud83d\udd38 VLAN Tag on {nic}: {vlan}")
    if gateway:
        logging.info(f"\ud83d\udd38 Gateway for {nic}: {gateway}")

def set_promiscuous_mode(nic: str):
    try:
        subprocess.run(["ip", "link", "set", nic, "promisc", "on"], check=True)
        logging.info(f"\ud83d\udd01 Promiscuous mode enabled for {nic}")
    except subprocess.CalledProcessError as e:
        logging.error(f"\u274c Failed to set promiscuous mode: {e}")
        sys.exit(1)

# --- New function for --scan ts using os_recorder ---
def collect_and_build_templates(host_ip, dest_path, nic):
    template_dict = defaultdict(dict)
    pair_dict = {}

    def handle_packet(pkt):
        try:
            packet = Packet(bytes(pkt))
            packet.interface = nic
            packet.unpack()
            proto = packet.l4 if packet.l4 else packet.l3
            templateSynthesis(packet, proto.upper(), template_dict, pair_dict, host_ip)
        except Exception as e:
            logging.debug(f"Failed to parse packet: {e}")

    logging.info(f"\ud83d\udcf1 Starting template learning on {nic} for 300s...")
    validate_nic(nic)
    set_promiscuous_mode(nic)
    time.sleep(1)
    sniff(iface=nic, timeout=300, prn=handle_packet, store=False)

    for proto in template_dict:
        output_txt = os.path.join(dest_path, f"{proto.lower()}_record.txt")
        encoded = {
            base64.b64encode(k).decode(): base64.b64encode(v).decode()
            for k, v in template_dict[proto].items() if v is not None
        }
        with open(output_txt, "w") as f:
            json.dump(encoded, f, indent=2)
        logging.info(f"\ud83d\udcc2 Saved {proto.upper()} templates to {output_txt}")

# --- Main Logic ---
def main():
    parser = argparse.ArgumentParser(description="\ud83d\udee1\ufe0f Camouflage Cloak: OS & Port Deception Engine")
    parser.add_argument("--host")
    parser.add_argument("--nic")
    parser.add_argument("--scan", choices=["ts", "od", "pd"])
    parser.add_argument("--os")
    parser.add_argument("--te", type=int)
    parser.add_argument("--status")
    parser.add_argument("--dest")
    parser.add_argument("--list-os", action="store_true")
    parser.add_argument("--debug", action="store_true")

    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.debug("\ud83d\udd0e Debug logging enabled.")

    if args.list_os:
        print("\n\ud83e\uddf0 Supported OS templates:")
        for name in settings.BASE_OS_TEMPLATES:
            print(f"  - {name} (TTL={settings.BASE_OS_TEMPLATES[name]['ttl']}, Window={settings.BASE_OS_TEMPLATES[name]['window']})")
        return

    if not args.nic:
        args.nic = settings.NIC_PROBE
        logging.info(f"\ud83d\udd0c Defaulting to NIC: {args.nic}")

    validate_nic(args.nic)

    if not args.host:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                args.host = s.getsockname()[0]
                logging.info(f"\ud83e\udde0 Auto-detected host IP from NIC: {args.host}")
        except Exception:
            logging.warning("\u26a0 Could not auto-detect host IP, defaulting to 127.0.0.1")
            args.host = "127.0.0.1"

    if args.scan == "ts":
        dest_path = os.path.abspath(args.dest or settings.OS_RECORD_PATH)
        ensure_directory_exists(dest_path)
        collect_and_build_templates(args.host, dest_path, args.nic)

    elif args.scan == "od":
        if not args.os or args.te is None:
            logging.error("\u274c Missing --os or --te")
            return
        os_name = args.os.lower()
        record_path = os.path.abspath(os.path.join(settings.OS_RECORD_PATH, os_name))
        deceiver = OsDeceiver(
            target_host=args.host,
            target_os=args.os,
            dest=record_path,
            nic=args.nic
        )
        deceiver.os_deceive(timeout_minutes=args.te)

    elif args.scan == "pd":
        if not args.status or args.te is None:
            logging.error("\u274c Missing --status or --te")
            return
        deceiver = PortDeceiver(
            interface_ip=args.host,
            nic=args.nic,
            os_name=args.os,
            ports_config=json.loads(args.status) if args.status.startswith('{') else None
        )
        deceiver.run()

if __name__ == '__main__':
    main()
