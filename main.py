import logging
import argparse
import os
import time
import sys
import subprocess
import json
import base64
import getpass

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
    from src.settings import MAC, VLAN_MAP, GATEWAY_MAP, BASE_OS_TEMPLATES
except ImportError as e:
    logging.error(f"\u274c Import Error: {e}")
    sys.exit(1)

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

def collect_fingerprint(target_host, dest, nic):
    logging.info(f"\ud83d\udcf1 Starting OS fingerprint collection on {target_host} via {nic}")
    ensure_directory_exists(dest)

    file_paths = {
        "arp": os.path.join(dest, "arp_record.pcap"),
        "icmp": os.path.join(dest, "icmp_record.pcap"),
        "tcp": os.path.join(dest, "tcp_record.pcap"),
        "udp": os.path.join(dest, "udp_record.pcap")
    }

    packet_buffers = {k: [] for k in file_paths}

    def classify_and_store(pkt):
        if pkt.haslayer("ARP"):
            packet_buffers["arp"].append(pkt)
        elif pkt.haslayer("IP"):
            if pkt.haslayer("TCP"):
                packet_buffers["tcp"].append(pkt)
            elif pkt.haslayer("UDP"):
                packet_buffers["udp"].append(pkt)
            elif pkt.haslayer("ICMP"):
                packet_buffers["icmp"].append(pkt)

    validate_nic(nic)
    set_promiscuous_mode(nic)
    time.sleep(2)

    logging.info("\ud83d\udce5 Sniffing packets for 600 seconds...")
    sniff(iface=nic, timeout=600, prn=classify_and_store, store=False)
    logging.info("\u2705 Packet capture completed.")

    total = 0
    for proto, pkts in packet_buffers.items():
        wrpcap(file_paths[proto], pkts)
        ensure_file_permissions(file_paths[proto])
        logging.info(f"\ud83d\udcc2 Saved {len(pkts)} {proto.upper()} packets to {file_paths[proto]}")
        total += len(pkts)

    logging.info(f"\u2705 Total packets saved: {total}")

def convert_raw_packets_to_template(file_path: str, proto: str):
    from src.fingerprint_utils import gen_key
    template_dict = {}

    try:
        packets = rdpcap(file_path)
        for pkt in packets:
            raw = bytes(pkt)
            if len(raw) < 42:
                continue
            key, _ = gen_key(proto, raw)
            template_dict[key] = raw

        encoded = {
            base64.b64encode(k).decode(): base64.b64encode(v).decode()
            for k, v in template_dict.items()
        }

        output_txt = file_path.replace(".pcap", ".txt")
        with open(output_txt, "w") as f:
            json.dump(encoded, f, indent=2)

        logging.info(f"\u2705 Converted {proto.upper()} packets to template: {output_txt}")
    except Exception as e:
        logging.error(f"\u274c Failed to convert {file_path}: {e}")

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

    if not args.nic or not args.scan:
        logging.error("\u274c Missing required arguments: --nic and --scan")
        parser.print_help()
        return

    validate_nic(args.nic)

    if not args.host:
        args.host = settings.IP_PROBE if args.nic == settings.NIC_PROBE else settings.IP_TARGET
        logging.info(f"\ud83e\udde0 Auto-detected host IP: {args.host}")

    if args.scan == "ts":
        dest_path = os.path.abspath(args.dest or settings.OS_RECORD_PATH)
        for proto in ["arp", "icmp", "tcp", "udp"]:
            for ext in [".pcap", ".txt"]:
                path = os.path.join(dest_path, f"{proto}_record{ext}")
                if os.path.exists(path):
                    os.remove(path)
        collect_fingerprint(args.host, dest_path, args.nic)
        for proto in ["arp", "icmp", "tcp", "udp"]:
            pcap = os.path.join(dest_path, f"{proto}_record.pcap")
            if os.path.exists(pcap):
                convert_raw_packets_to_template(pcap, proto)

    elif args.scan == "od":
        if not args.os or args.te is None:
            logging.error("\u274c Missing --os or --te")
            return
        os_name = args.os.lower()
        record_path = os.path.abspath(os.path.join(settings.OS_RECORD_PATH, os_name))
        for proto in ["arp", "icmp", "tcp", "udp"]:
            full_path = os.path.join(record_path, f"{proto}_record.pcap")
            convert_raw_packets_to_template(full_path, proto)
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
        deceiver = PortDeceiver(args.host, nic=args.nic)
        deceiver.deceive_ps_hs(args.status)

if __name__ == '__main__':
    main()
