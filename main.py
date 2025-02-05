import logging
import argparse
import os
import sys

# Ensure `src` is in Python's module search path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "src")))

import src.settings as settings
from src.port_deceiver import PortDeceiver
from src.os_deceiver import OsDeceiver
from src.utils import is_valid_ip, is_valid_mac

logging.basicConfig(
    format="%(asctime)s [%(levelname)s]: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    level=logging.INFO
)

def main():
    parser = argparse.ArgumentParser(description="Camouflage Cloak - Main Execution")
    parser.add_argument("--host", action="store", required=True, help="Specify target server IP")
    parser.add_argument("--port", action="store", help="Specify destination port")
    parser.add_argument("--nic", action="store", required=True, help="NIC where we capture the packets")
    parser.add_argument("--scan", action="store", required=True, help="Attacker's port scanning technique")
    parser.add_argument("--status", action="store", help="Designate port status (required for 'pd' scan)")
    parser.add_argument("--os", action="store", help="Designate OS we want to deceive")
    parser.add_argument("--output-dir", action="store", help="Specify output directory for storing records")

    args = parser.parse_args()

    # Validate the target host IP
    if not is_valid_ip(args.host):
        logging.error(f"Invalid target server IP: {args.host}")
        sys.exit(1)

    # Validate NIC
    if args.nic != settings.CLOAK_NIC:
        logging.error(f"Invalid NIC: {args.nic}. Expected: {settings.CLOAK_NIC}")
        sys.exit(1)

    # Assign local variables
    target_server = args.host
    output_dir = args.output_dir if args.output_dir else settings.TARGET_OS_OUTPUT_DIR
    os_type = args.os if args.os else settings.TARGET_SERVER_OS
    scan_type = args.scan.lower()

    # Ensure output directory exists
    os.makedirs(output_dir, exist_ok=True)

    # Log configuration
    logging.info(f"Configuration: Target Server={target_server}, OS={os_type}, Output Dir={output_dir}, NIC={args.nic}")

    # Execute based on the selected scanning technique
    if scan_type == "ts":
        logging.info(f"Executing TS scan on {target_server}, storing results in {output_dir}")
        deceiver = OsDeceiver(target_server, os_type)
        deceiver.os_record(output_path=output_dir)

    elif scan_type == "od":
        logging.info(f"Executing OS deception for {target_server} using {os_type}")
        deceiver = OsDeceiver(target_server, os_type)
        deceiver.os_deceive(output_path=output_dir)

    elif scan_type == "rr":
        logging.info(f"Recording responses from {target_server}")
        deceiver = OsDeceiver(target_server, os_type)
        deceiver.store_rsp(output_path=output_dir)

    elif scan_type == "pd":
        if not args.status:
            logging.error("Port status must be specified for 'pd' scan")
            sys.exit(1)
        logging.info(f"Executing Port Deception for {target_server} with status {args.status}")
        deceiver = PortDeceiver(target_server)
        deceiver.deceive_ps_hs(args.status, output_path=output_dir)

    else:
        logging.error("Invalid port scan technique specified.")
        sys.exit(1)

if __name__ == "__main__":
    main()
