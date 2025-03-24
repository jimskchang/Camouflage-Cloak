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
    from src.settings import MAC
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

def convert_raw_packets_to_template(file_path: str, proto: str):
    from src.os_deceiver import gen_key
    template_dict = {}

    try:
        with open(file_path, "rb") as f:
            lines = f.read().split(b"\n")

        for raw in lines:
            if not raw or len(raw) < 42:
                continue
            key, _ = gen_key(proto, raw)
            template_dict[key] = raw

        encoded = {
            base64.b64encode(k).decode(): base64.b64encode(v).decode()
            for k, v in template_dict.items()
        }
        with open(file_path, "w") as f:
            json.dump(encoded, f, indent=2)

        logging.info(f"✅ Converted raw {proto} packets in {file_path} to JSON template.")
    except Exception as e:
        logging.error(f"❌ Failed to convert {file_path}: {e}")

def list_supported_os():
    print("🧩 Supported OS templates:")
    for name, conf in settings.OS_TEMPLATES.items():
        print(f"  - {name} (TTL={conf['ttl']}, Window={conf['window']})")

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

    # Handle --debug first
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.debug("🐞 Debug logging enabled.")

    # Handle --list-os early exit
    if args.list_os:
        list_supported_os()
        return

    if not args.host or not args.nic or not args.scan:
        logging.error("❌ Missing required arguments: --host, --nic, --scan")
        parser.print_help()
        return

    validate_nic(args.nic)

    if args.scan == 'ts':
        dest = args.dest or settings.OS_RECORD_PATH
        collect_fingerprint(args.host, dest, args.nic)

    elif args.scan == 'od':
        if not args.os or args.te is None:
            logging.error("❌ Missing required arguments --os or --te for OS deception")
            return

        os_name = args.os.lower()
        if os_name not in settings.OS_TEMPLATES:
            logging.error(f"❌ Unknown OS template '{args.os}'. Available templates: {', '.join(settings.OS_TEMPLATES.keys())}")
            return

        spoof_config = settings.OS_TEMPLATES[os_name]
        logging.info(f"🎭 Using OS template '{os_name}': TTL={spoof_config['ttl']}, Window={spoof_config['window']}")

        os_record_path = os.path.join(settings.OS_RECORD_PATH, os_name)
        ensure_directory_exists(os_record_path)

        proto_map = {
            "arp_record.txt": "arp",
            "tcp_record.txt": "tcp",
            "udp_record.txt": "udp",
            "icmp_record.txt": "icmp"
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
