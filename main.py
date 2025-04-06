# main.py
import logging
import argparse
import os
import sys
import time
import socket
import json
import base64
import subprocess
from collections import defaultdict
from scapy.all import sniff, wrpcap, get_if_hwaddr

# -- Setup path --
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SRC_DIR = os.path.join(BASE_DIR, "src")
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)

# -- Logging --
logging.basicConfig(
    format='%(asctime)s [%(levelname)s]: %(message)s',
    datefmt='%-y-%m-%d %H:%M:%S',
    level=logging.INFO
)

# -- Imports --
try:
    import src.settings as settings
    from src.settings import VLAN_MAP, GATEWAY_MAP, BASE_OS_TEMPLATES
    from src.fingerprint_utils import gen_key
    from src.os_recorder import templateSynthesis
except ImportError as e:
    logging.error(f"❌ Import error: {e}")
    sys.exit(1)

# -- Utilities --
def ensure_directory_exists(path: str):
    try:
        os.makedirs(path, exist_ok=True)
        logging.info(f"📁 Ensured directory exists: {path}")
    except Exception as e:
        logging.error(f"❌ Failed to create directory {path}: {e}")
        sys.exit(1)

def validate_nic(nic: str):
    path = f"/sys/class/net/{nic}"
    if not os.path.exists(path):
        logging.error(f"❌ Network interface {nic} not found.")
        sys.exit(1)
    try:
        mac = get_if_hwaddr(nic)
        logging.info(f"✅ NIC {nic} MAC address: {mac}")
    except Exception as e:
        logging.warning(f"⚠ Could not retrieve MAC for {nic}: {e}")
    vlan = VLAN_MAP.get(nic)
    gateway = GATEWAY_MAP.get(nic)
    if vlan: logging.info(f"🔷 VLAN Tag on {nic}: {vlan}")
    if gateway: logging.info(f"🔷 Gateway: {gateway}")

def set_promiscuous_mode(nic: str):
    try:
        subprocess.run(["ip", "link", "set", nic, "promisc", "on"], check=True)
        logging.info(f"🔁 Promiscuous mode enabled for {nic}")
    except Exception as e:
        logging.error(f"❌ Could not set promiscuous mode: {e}")
        sys.exit(1)

def get_ip_for_nic(nic: str) -> str:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"

# -- Template Recorder --
def collect_and_build_templates(host_ip, dest_path, nic):
    from src.Packet import Packet

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
            logging.debug(f"[!] Packet parsing error: {e}")

    logging.info(f"📡 Template capture on {nic} (300s)")
    validate_nic(nic)
    set_promiscuous_mode(nic)
    time.sleep(1)
    sniff(iface=nic, timeout=300, prn=handle, store=False)

    for proto in template_dict:
        file = os.path.join(dest_path, f"{proto.lower()}_record.txt")
        encoded = {
            base64.b64encode(k).decode(): base64.b64encode(v).decode()
            for k, v in template_dict[proto].items() if v
        }
        with open(file, "w") as f:
            json.dump(encoded, f, indent=2)
        logging.info(f"📦 Saved {proto.upper()} templates to {file}")

# -- Main Logic --
def main():
    parser = argparse.ArgumentParser(description="🛡️ Camouflage Cloak - Deception Engine")
    parser.add_argument("--scan", choices=["ts", "od", "pd"])
    parser.add_argument("--host")
    parser.add_argument("--nic")
    parser.add_argument("--os")
    parser.add_argument("--te", type=int)
    parser.add_argument("--status")
    parser.add_argument("--dest")
    parser.add_argument("--replay", action="store_true")
    parser.add_argument("--interactive", action="store_true")
    parser.add_argument("--list-os", action="store_true")
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.debug("🔎 Debug mode activated")

    if args.list_os:
        print("\n📚 Available OS templates:")
        for name in settings.BASE_OS_TEMPLATES:
            print(f"  - {name}")
        return

    if not args.nic:
        args.nic = settings.NIC_PROBE
        logging.info(f"🧩 Using default NIC: {args.nic}")
    validate_nic(args.nic)

    if not args.host:
        args.host = get_ip_for_nic(args.nic)
        logging.info(f"🌐 Detected host IP: {args.host}")

    mac = get_if_hwaddr(args.nic)

    # -- Template Recorder --
    if args.scan == "ts":
        dest_path = os.path.abspath(args.dest or settings.OS_RECORD_PATH)
        ensure_directory_exists(dest_path)
        collect_and_build_templates(args.host, dest_path, args.nic)

    # -- OS Deception --
    elif args.scan == "od":
        if not args.os or args.te is None:
            logging.error("❌ Missing required --os or --te")
            return
        from src.os_deceiver import OsDeceiver
        record_path = os.path.join(settings.OS_RECORD_PATH, args.os.lower())
        od = OsDeceiver(args.host, args.os, dest=record_path, nic=args.nic)
        od.os_deceive(timeout_minutes=args.te)

    # -- Port Deception --
    elif args.scan == "pd":
        if not args.status or args.te is None:
            logging.error("❌ Missing required --status or --te")
            return
        try:
            port_map = json.loads(args.status)
        except Exception as e:
            logging.error(f"❌ Failed to parse --status: {e}")
            return
        from src.port_deceiver import PortDeceiver
        pd = PortDeceiver(args.host, args.nic, args.os, port_map)
        pd.run()

    # -- Simulated Replay --
    elif args.replay:
        from src.os_deceiver import OsDeceiver
        from src.port_deceiver import PortDeceiver
        logging.info("🎮 Starting simulated replay mode")
        od = OsDeceiver(args.host, args.os or "win10", nic=args.nic)
        od.replay_templates()
        pd = PortDeceiver(args.host, args.nic, args.os or "win10", {})
        pd.replay_port_behavior()

    # -- Interactive Editor --
    elif args.interactive:
        from src.interactive_editor import InteractiveCLI
        logging.info("🧠 Starting live interactive control panel")
        cli = InteractiveCLI(nic=args.nic)
        cli.run()

    else:
        logging.warning("⚠ No --scan or mode specified. Use --help for options.")

if __name__ == "__main__":
    main()
