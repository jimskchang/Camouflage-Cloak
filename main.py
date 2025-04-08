import logging
import argparse
import os
import sys
import time
import socket
import subprocess
import json
import base64
from collections import defaultdict
from scapy.all import sniff, wrpcap, get_if_hwaddr

# --- Path Setup ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SRC_DIR = os.path.join(BASE_DIR, "src")
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)

# --- Logging ---
logging.basicConfig(
    format='%(asctime)s [%(levelname)s]: %(message)s',
    datefmt='%-y-%m-%d %H:%M:%S',
    level=logging.INFO
)

# --- Imports ---
try:
    import src.settings as settings
    from src.port_deceiver import PortDeceiver
    from src.os_deceiver import OsDeceiver
    from src.fingerprint_gen import generateKey
    from src.os_recorder import templateSynthesis
    from src.Packet import Packet
except ImportError as e:
    logging.error(f"[ERROR]: Import error: {e}")
    sys.exit(1)

# --- Utils ---
def ensure_directory_exists(path):
    try:
        os.makedirs(path, exist_ok=True)
        logging.info(f"📁 Ensured output path exists: {path}")
    except Exception as e:
        logging.error(f"[ERROR]: Failed to create directory {path}: {e}")
        sys.exit(1)

def validate_nic(nic: str):
    if not os.path.exists(f"/sys/class/net/{nic}"):
        logging.error(f"[ERROR]: NIC {nic} not found.")
        sys.exit(1)
    try:
        mac = get_if_hwaddr(nic)
        logging.info(f"✅ Interface {nic} MAC: {mac}")
    except Exception as e:
        logging.warning(f"[WARN]: Could not fetch MAC for {nic}: {e}")

def set_promiscuous_mode(nic: str):
    try:
        subprocess.run(["ip", "link", "set", nic, "promisc", "on"], check=True)
        logging.info(f"🔁 Promiscuous mode enabled for {nic}")
    except subprocess.CalledProcessError as e:
        logging.error(f"[ERROR]: Failed to enable promiscuous mode: {e}")
        sys.exit(1)

def get_ip_for_nic(nic: str) -> str:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except Exception:
        logging.warning("⚠ Could not resolve NIC IP, fallback to 127.0.0.1")
        return "127.0.0.1"

# --- Template Builder ---
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
            logging.debug(f"[WARN]: Could not parse packet: {e}")

    logging.info(f"📡 Learning templates on NIC={nic}, host={host_ip}")
    validate_nic(nic)
    set_promiscuous_mode(nic)
    time.sleep(1)
    sniff(iface=nic, timeout=300, prn=handle_packet, store=False)

    for proto in template_dict:
        outfile = os.path.join(dest_path, f"{proto.lower()}_record.txt")
        encoded = {
            base64.b64encode(k).decode(): base64.b64encode(v).decode()
            for k, v in template_dict[proto].items() if v is not None
        }
        with open(outfile, "w") as f:
            json.dump(encoded, f, indent=2)
        logging.info(f"💾 Saved {proto.upper()} templates to {outfile}")

# --- Main Entry ---
def main():
    parser = argparse.ArgumentParser(description="🛡️ Camouflage Cloak: OS & Port Deception")
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

    if args.list_os:
        print("\n🧠 Supported OS Templates:")
        for osname in settings.list_all_templates():
            print(f"  - {osname}")
        return

    if not args.nic:
        args.nic = settings.NIC_PROBE
        logging.info(f"[INFO]: Defaulting NIC to {args.nic}")

    validate_nic(args.nic)

    if not args.host:
        args.host = get_ip_for_nic(args.nic)
        logging.info(f"[INFO]: Auto-detected host IP: {args.host}")

    mac = get_if_hwaddr(args.nic)

    if args.scan == "ts":
        dest_path = os.path.abspath(args.dest or settings.OS_RECORD_PATH)
        ensure_directory_exists(dest_path)
        collect_and_build_templates(args.host, dest_path, args.nic)

    elif args.scan == "od":
        if not args.os or args.te is None:
            logging.error("❌ --os and --te required for OS deception mode")
            return
        dest_path = os.path.abspath(os.path.join(settings.OS_RECORD_PATH, args.os))
        deceiver = OsDeceiver(
            target_host=args.host,
            target_os=args.os,
            dest=dest_path,
            nic=args.nic
        )
        deceiver.os_deceive(timeout_minutes=args.te)

    elif args.scan == "pd":
        if not args.status or args.te is None:
            logging.error("❌ --status and --te required for port deception mode")
            return
        try:
            port_map = json.loads(args.status)
        except Exception as e:
            logging.error(f"❌ Invalid --status JSON: {e}")
            return
        deceiver = PortDeceiver(
            interface_ip=args.host,
            os_name=args.os,
            ports_config=port_map,
            nic=args.nic,
            mac=mac
        )
        deceiver.run()

if __name__ == '__main__':
    main()
