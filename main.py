# main.py
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
from scapy.all import sniff, wrpcap, get_if_hwaddr

# --- Setup path ---
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
    from src.fingerprint_utils import gen_key
    from src.fingerprint_gen import generateKey
    from src.os_recorder import templateSynthesis
    from src.Packet import Packet
    from src.settings import VLAN_MAP, GATEWAY_MAP, BASE_OS_TEMPLATES
except ImportError as e:
    logging.error(f"❌ Import Error: {e}")
    sys.exit(1)

# --- Utilities ---
def ensure_directory_exists(directory: str):
    os.makedirs(directory, exist_ok=True)
    logging.info(f"📁 Ensured directory: {directory}")

def validate_nic(nic: str):
    if not os.path.exists(f"/sys/class/net/{nic}"):
        logging.error(f"NIC {nic} not found.")
        sys.exit(1)
    try:
        mac = get_if_hwaddr(nic)
        logging.info(f"✅ {nic} MAC: {mac}")
    except Exception as e:
        logging.warning(f"MAC read failed: {e}")
    vlan = VLAN_MAP.get(nic)
    gw = GATEWAY_MAP.get(nic)
    if vlan:
        logging.info(f"VLAN for {nic}: {vlan}")
    if gw:
        logging.info(f"Gateway for {nic}: {gw}")

def set_promiscuous_mode(nic: str):
    try:
        subprocess.run(["ip", "link", "set", nic, "promisc", "on"], check=True)
        logging.info(f"🔁 Promiscuous ON for {nic}")
    except Exception as e:
        logging.error(f"Failed promisc mode: {e}")

def get_ip_for_nic(nic: str) -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except:
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
            proto = packet.l4 or packet.l3
            templateSynthesis(packet, proto.upper(), template_dict, pair_dict, host_ip)
        except Exception as e:
            logging.debug(f"Parsing error: {e}")

    logging.info(f"📱 Learning templates on {nic}...")
    validate_nic(nic)
    set_promiscuous_mode(nic)
    sniff(iface=nic, timeout=300, prn=handle_packet, store=False)

    for proto in template_dict:
        output_txt = os.path.join(dest_path, f"{proto.lower()}_record.txt")
        encoded = {
            base64.b64encode(k).decode(): base64.b64encode(v).decode()
            for k, v in template_dict[proto].items() if v is not None
        }
        with open(output_txt, "w") as f:
            json.dump(encoded, f, indent=2)
        logging.info(f"Saved {proto} to {output_txt}")

# --- Main Entry ---
def main():
    parser = argparse.ArgumentParser(description="🛡️ Camouflage Cloak")
    parser.add_argument("--host")
    parser.add_argument("--nic")
    parser.add_argument("--scan", choices=["ts", "od", "pd"])
    parser.add_argument("--os")
    parser.add_argument("--te", type=int)
    parser.add_argument("--status")
    parser.add_argument("--dest")
    parser.add_argument("--debug", action="store_true")
    parser.add_argument("--list-os", action="store_true")
    parser.add_argument("--replay", action="store_true")
    parser.add_argument("--interactive", action="store_true")

    args = parser.parse_args()
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    if args.list_os:
        print("\n🧰 OS Templates:")
        for name in settings.BASE_OS_TEMPLATES:
            print(f"- {name}")
        return

    if not args.nic:
        args.nic = settings.NIC_PROBE
        logging.info(f"Default NIC: {args.nic}")
    validate_nic(args.nic)

    if not args.host:
        args.host = get_ip_for_nic(args.nic)
        logging.info(f"Auto host IP: {args.host}")

    mac = get_if_hwaddr(args.nic)

    if args.replay:
        logging.info("🔄 Replay mode enabled (template re-testing)")
        # TODO: Implement replay mode logic
        return

    if args.interactive:
        logging.info("📍 Launching interactive rule editor...")
        # TODO: Implement interactive mode
        return

    if args.scan == "ts":
        dest = os.path.abspath(args.dest or settings.OS_RECORD_PATH)
        ensure_directory_exists(dest)
        collect_and_build_templates(args.host, dest, args.nic)

    elif args.scan == "od":
        if not args.os or args.te is None:
            logging.error("Missing --os or --te")
            return
        record_path = os.path.join(settings.OS_RECORD_PATH, args.os.lower())
        deceiver = OsDeceiver(
            target_host=args.host,
            target_os=args.os,
            dest=record_path,
            nic=args.nic
        )
        deceiver.os_deceive(timeout_minutes=args.te)

    elif args.scan == "pd":
        if not args.status or args.te is None:
            logging.error("Missing --status or --te")
            return
        try:
            ports = json.loads(args.status)
        except Exception as e:
            logging.error(f"Status JSON error: {e}")
            return
        deceiver = PortDeceiver(
            interface_ip=args.host,
            os_name=args.os,
            ports_config=ports,
            nic=args.nic,
            mac=mac
        )
        deceiver.run()

if __name__ == '__main__':
    main()
