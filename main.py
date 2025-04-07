import os
import sys
import logging
import argparse
import json
import time
import subprocess
from collections import defaultdict
from scapy.all import sniff, wrpcap, get_if_hwaddr

# Add src to sys.path
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SRC_DIR = os.path.join(BASE_DIR, "src")
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)

# --- Logging ---
logging.basicConfig(
    format='%(asctime)s [%(levelname)s]: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
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

# --- Utility Functions ---
def ensure_dir(path):
    try:
        os.makedirs(path, exist_ok=True)
        logging.info(f"[+] Created directory: {path}")
    except Exception as e:
        logging.error(f"[ERROR]: Could not create directory {path}: {e}")


def validate_nic(nic):
    if not os.path.exists(f"/sys/class/net/{nic}"):
        logging.error(f"[ERROR]: NIC {nic} not found.")
        sys.exit(1)
    try:
        mac = get_if_hwaddr(nic)
        logging.info(f"[NIC] {nic} MAC: {mac}")
    except Exception as e:
        logging.warning(f"[WARN] Could not get MAC for {nic}: {e}")


def set_promiscuous(nic):
    try:
        subprocess.run(["ip", "link", "set", nic, "promisc", "on"], check=True)
        logging.info(f"[+] Promiscuous mode enabled for {nic}")
    except subprocess.CalledProcessError:
        logging.warning(f"[WARN] Failed to enable promiscuous mode for {nic}")


# --- Template Builder ---
def capture_templates(host_ip, dest_path, nic, enable_l7=False):
    template_dict = defaultdict(dict)
    pair_dict = {}

    def handler(pkt):
        try:
            packet = Packet(bytes(pkt))
            packet.interface = nic
            packet.unpack()
            proto = packet.l4 if packet.l4 else packet.l3
            templateSynthesis(packet, proto.upper(), template_dict, pair_dict, host_ip)
        except Exception as e:
            logging.debug(f"[WARN] Packet parse failed: {e}")

    logging.info(f"[+] Capturing fingerprints on NIC {nic} for 300s...")
    validate_nic(nic)
    set_promiscuous(nic)
    time.sleep(1)
    sniff(iface=nic, timeout=300, prn=handler, store=False)

    for proto in template_dict:
        output_txt = os.path.join(dest_path, f"{proto.lower()}_record.txt")
        encoded = {
            key.hex(): value.hex() if value else None
            for key, value in template_dict[proto].items()
        }
        with open(output_txt, "w") as f:
            json.dump(encoded, f, indent=2)
        logging.info(f"[+] Saved {proto} templates to {output_txt}")


# --- Main Entrypoint ---
def main():
    parser = argparse.ArgumentParser(description="🛡️ Camouflage Cloak: OS & Port Deception")
    parser.add_argument("--host", help="Target IP (used in TS or OD mode)")
    parser.add_argument("--nic", help="Network interface to monitor")
    parser.add_argument("--scan", choices=["ts", "od", "pd"], help="Mode: ts=learn, od=os deceive, pd=port deceive")
    parser.add_argument("--os", help="OS template name")
    parser.add_argument("--te", type=int, help="Timeout (minutes)")
    parser.add_argument("--status", help="JSON string of port statuses for PD mode")
    parser.add_argument("--dest", help="Destination directory for template export")
    parser.add_argument("--l7", action="store_true", help="Enable L7 extraction (DNS/JA3/HTTP)")
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.debug("[DEBUG] Verbose mode enabled.")

    if not args.nic:
        logging.error("[ERROR] --nic required")
        return

    validate_nic(args.nic)

    if args.scan == "ts":
        if not args.host:
            logging.error("[ERROR] --host required for TS mode")
            return
        dest_path = os.path.abspath(args.dest or settings.OS_RECORD_PATH)
        ensure_dir(dest_path)
        capture_templates(args.host, dest_path, args.nic, enable_l7=args.l7)

    elif args.scan == "od":
        if not args.host or not args.os or not args.te:
            logging.error("[ERROR] --host, --os, --te required for OD mode")
            return
        record_path = os.path.join(settings.OS_RECORD_PATH, args.os.lower())
        ensure_dir(record_path)
        deceiver = OsDeceiver(
            target_host=args.host,
            target_os=args.os,
            dest=record_path,
            nic=args.nic
        )
        deceiver.os_deceive(timeout_minutes=args.te)

    elif args.scan == "pd":
        if not args.host or not args.status or not args.te:
            logging.error("[ERROR] --host, --status, --te required for PD mode")
            return
        try:
            port_map = json.loads(args.status)
        except Exception as e:
            logging.error(f"[ERROR] Invalid JSON for --status: {e}")
            return
        deceiver = PortDeceiver(
            interface_ip=args.host,
            os_name=args.os,
            ports_config=port_map,
            nic=args.nic,
            mac=get_if_hwaddr(args.nic)
        )
        deceiver.run()

if __name__ == "__main__":
    main()
