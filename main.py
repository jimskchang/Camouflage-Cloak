import logging
import argparse
import os
import sys

# Ensure correct module path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# Import settings and dependencies
try:
    import settings
except ImportError:
    logging.warning("Failed to import settings.py. Using default values.")
    settings = None

from port_deceiver import PortDeceiver
from os_deceiver import OsDeceiver

logging.basicConfig(
    format="%(asctime)s [%(levelname)s]: %(message)s",
    datefmt="%y-%m-%d %H:%M",
    level=logging.INFO,
)


def main():
    parser = argparse.ArgumentParser(description="Deceiver Demo")
    parser.add_argument("--host", required=True, help="Specify destination IP")
    parser.add_argument("--port", help="Specify destination port")
    parser.add_argument("--nic", required=True, help="NIC where we capture the packets")
    parser.add_argument("--scan", required=True, help="Attacker's port scanning technique")
    parser.add_argument("--status", help="Designate port status")
    parser.add_argument("--os", help="Designate OS we want to deceive", default="unknown")
    parser.add_argument("--dest", help="Specify file storage location")

    args = parser.parse_args()
    settings.host = args.host
    settings.NIC = args.nic

    # Ensure output directory
    os_record_dir = settings.get_os_record_dir(args.dest if args.dest else None)

    if not os.path.exists(os_record_dir):
        logging.info(f"Creating output directory: {os_record_dir}")
        os.makedirs(os_record_dir, exist_ok=True)

    # Fix: Ensure OS name is passed properly
    os_name = args.os if args.os else "unknown"

    port_scan_tech = args.scan

    if port_scan_tech == "ts":
        deceiver = OsDeceiver(args.host, os_name)
        deceiver.os_record(output_path=os_record_dir)
    elif port_scan_tech == "od":
        if os_name == "unknown":
            logging.debug("No OS is designated")
        else:
            deceiver = OsDeceiver(args.host, os_name)
            deceiver.os_deceive(output_path=os_record_dir)
    elif port_scan_tech == "rr":
        deceiver = OsDeceiver(args.host, os_name)
        deceiver.store_rsp(output_path=os_record_dir)
    elif port_scan_tech == "pd":
        if args.status:
            deceiver = PortDeceiver(args.host)
            deceiver.deceive_ps_hs(args.status, output_path=os_record_dir)
        else:
            logging.error("Port status must be specified for PD scan")
            return
    else:
        logging.error("Invalid port scan technique specified")
        return


if __name__ == "__main__":
    main()
