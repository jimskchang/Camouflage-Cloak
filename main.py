import logging
import argparse
import os
import time
import sys
import subprocess
import json
import base64

from scapy.all import sniff, wrpcap, rdpcap

# --- Ensure src is in sys.path ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SRC_DIR = os.path.join(BASE_DIR, "src")
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)

# --- Initial Basic Logging ---
logging.basicConfig(
    format='%(asctime)s [%(levelname)s]: %(message)s',
    datefmt='%y-%m-%d %H:%M:%S',
    level=logging.INFO
)

# --- Safe Imports ---
try:
    import src.settings as settings
    from src.port_deceiver import PortDeceiver
    from src.os_deceiver import OsDeceiver
    from src.settings import MAC, VLAN_MAP, GATEWAY_MAP, BASE_OS_TEMPLATES
except ImportError as e:
    logging.error(f"❌ Import Error: {e}")
    sys.exit(1)

# --- Utility Functions ---
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

    vlan = VLAN_MAP.get(nic)
    gateway = GATEWAY_MAP.get(nic)
    if vlan:
        logging.info(f"🔸 VLAN Tag on {nic}: {vlan}")
    if gateway:
        logging.info(f"🔸 Gateway for {nic}: {gateway}")

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

    file_paths = {
        "arp": os.path.join(dest, "arp_record.pcap"),
        "icmp": os.path.join(dest, "icmp_record.pcap"),
        "tcp": os.path.join(dest, "tcp_record.pcap"),
        "udp": os.path.join(dest, "udp_record.pcap")
    }

    packet_buffers = {
        "arp": [],
        "icmp": [],
        "tcp": [],
        "udp": []
    }

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

    logging.info("📥 Sniffing packets for 600 seconds...")
    sniff(iface=nic, timeout=600, prn=classify_and_store, store=False)
    logging.info("✅ Packet capture completed.")

    total = 0
    for proto, pkts in packet_buffers.items():
        wrpcap(file_paths[proto], pkts)
        ensure_file_permissions(file_paths[proto])
        logging.info(f"💾 Saved {len(pkts)} {proto.upper()} packets to {file_paths[proto]}")
        total += len(pkts)

    logging.info(f"✅ Total packets saved: {total}")

def convert_raw_packets_to_template(file_path: str, proto: str):
    from src.os_deceiver import gen_key
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

        logging.info(f"✅ Converted {proto.upper()} packets to template: {output_txt}")
    except Exception as e:
        logging.error(f"❌ Failed to convert {file_path}: {e}")

def list_supported_os():
    print("🧩 Supported OS templates:")
    for name in BASE_OS_TEMPLATES:
        print(f"  - {name} (TTL={BASE_OS_TEMPLATES[name]['ttl']}, Window={BASE_OS_TEMPLATES[name]['window']})")
    if settings.OS_ALIASES:
        print("\n🔁 Aliases:")
        for alias, base in settings.OS_ALIASES.items():
            print(f"  - {alias} → {base}")

# --- Main Logic ---
def main():
    parser = argparse.ArgumentParser(description="🛡️ Camouflage Cloak: OS & Port Deception Engine")
    parser.add_argument("--host", help="Target IP to impersonate")
    parser.add_argument("--nic", help="Network interface to bind")
    parser.add_argument("--scan", choices=["ts", "od", "pd"], help="Scan mode: ts, od, pd")
    parser.add_argument("--os", help="OS template to mimic (for --scan od)")
    parser.add_argument("--te", type=int, help="Timeout in minutes (for --scan od/pd)")
    parser.add_argument("--status", help="Port status: open or close (for --scan pd)")
    parser.add_argument("--dest", help="Optional destination path for OS fingerprint collection")
    parser.add_argument("--list-os", action="store_true", help="List available OS templates and exit")
    parser.add_argument("--debug", action="store_true", help="Enable debug-level logging")

    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.debug("🐞 Debug logging enabled.")

    if args.list_os:
        list_supported_os()
        return

    if not args.nic or not args.scan:
        logging.error("❌ Missing required arguments: --nic and --scan")
        parser.print_help()
        return

    validate_nic(args.nic)

    if not args.host:
        if args.nic == settings.NIC_PROBE:
            args.host = settings.IP_PROBE
        elif args.nic == settings.NIC_TARGET:
            args.host = settings.IP_TARGET
        else:
            logging.error("❌ Cannot infer IP from unknown NIC. Please provide --host explicitly.")
            return
        logging.info(f"🧠 Auto-detected host IP from NIC {args.nic}: {args.host}")

    gateway = GATEWAY_MAP.get(args.nic, "unknown")
    logging.info(f"🌐 Using gateway {gateway} for interface {args.nic}")

    if args.scan == 'ts':
        dest_path = os.path.abspath(args.dest) if args.dest else os.path.abspath(settings.OS_RECORD_PATH)

        # 🧹 Always clean old files before capture
        for proto in ["arp", "icmp", "tcp", "udp"]:
            for ext in [".pcap", ".txt"]:
                path = os.path.join(dest_path, f"{proto}_record{ext}")
                if os.path.exists(path):
                    os.remove(path)
                    logging.info(f"🧹 Deleted old file: {path}")

        # 📡 Capture new fingerprint
        collect_fingerprint(args.host, dest_path, args.nic)

        # 🛠️ Auto-generate .txt templates
        for proto in ["arp", "icmp", "tcp", "udp"]:
            pcap_file = os.path.join(dest_path, f"{proto}_record.pcap")
            if os.path.exists(pcap_file):
                convert_raw_packets_to_template(pcap_file, proto)

    elif args.scan == 'od':
        if not args.os or args.te is None:
            logging.error("❌ Missing required arguments --os or --te for OS deception")
            return

        os_name = args.os.lower()
        spoof_config = settings.get_os_fingerprint(os_name)

        if not spoof_config:
            logging.error(f"❌ Unable to load OS fingerprint for '{args.os}'")
            return

        logging.info(f"🎭 Using OS template '{os_name}': TTL={spoof_config['ttl']}, Window={spoof_config['window']}")

        os_record_path = os.path.abspath(os.path.join(settings.OS_RECORD_PATH, os_name))
        if not os.path.isdir(os_record_path):
            logging.error(f"❌ OS fingerprint directory not found: {os_record_path}")
            return

        proto_map = {
            "arp_record.pcap": "arp",
            "tcp_record.pcap": "tcp",
            "udp_record.pcap": "udp",
            "icmp_record.pcap": "icmp"
        }

        for fname, proto in proto_map.items():
            full_path = os.path.join(os_record_path, fname)
            convert_raw_packets_to_template(full_path, proto)

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
