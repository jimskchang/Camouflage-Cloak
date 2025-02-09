import logging
import argparse
import os
import sys

# Ensure the `src` directory is in the Python module path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "src")))

# Import settings and dependencies
try:
    import settings
except ImportError:
    logging.error("Failed to import settings.py. Ensure the file exists. Exiting...")
    sys.exit(1)

from src.port_deceiver import PortDeceiver
from src.os_deceiver import OsDeceiver

# Configure logging
logging.basicConfig(
    format="%(asctime)s [%(levelname)s]: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    level=logging.INFO
)

def main():
    """Main function to parse arguments and execute the deception techniques."""

    parser = argparse.ArgumentParser(description="Deceiver Demo")
    parser.add_argument("--host", required=True, help="Specify destination IP")
    parser.add_argument("--port", type=int, help="Specify destination port (optional)")
    parser.add_argument("--nic", required=True, help="Network interface (NIC) for packet capture")
    parser.add_argument("--scan", required=True, help="Attacker's port scanning technique (ts, od, rr, pd)")
    parser.add_argument("--status", help="Specify port status (optional, required for pd scan)")
    parser.add_argument("--os", help="Specify OS to deceive (optional, required for 'od' scan)")

    args = parser.parse_args()

    # Validate NIC before assignment
    if not os.path.exists(f"/sys/class/net/{args.nic}"):
        logging.error(f"Network interface '{args.nic}' does not exist. Please check your NIC settings.")
        sys.exit(1)

    # Assign values to settings (ensuring they exist)
    settings.HOST = args.host
    settings.NIC = args.nic

    # Ensure a valid scan technique is provided
    port_scan_tech = args.scan.lower()
    valid_scan_techniques = {"ts", "od", "rr", "pd"}

    if port_scan_tech not in valid_scan_techniques:
        logging.error(f"Invalid scan technique '{port_scan_tech}'. Choose from {valid_scan_techniques}.")
        sys.exit(1)

    deceiver = None  # Initialize before use

    # Handle deception based on scan technique
    if port_scan_tech == "ts":
        logging.info("Executing TCP/IP stack deception...")
        deceiver = OsDeceiver(args.host, args.os or "default_os")
        deceiver.os_record()

    elif port_scan_tech == "od":
        if not args.os:
            logging.error("OS deception requires an '--os' argument. Exiting...")
            sys.exit(1)
        logging.info(f"Executing OS deception for {args.os}...")
        deceiver = OsDeceiver(args.host, args.os)
        deceiver.os_deceive()

    elif port_scan_tech == "rr":
        logging.info("Executing response recording...")
        deceiver = OsDeceiver(args.host, args.os or "default_os")
        deceiver.store_rsp()

    elif port_scan_tech == "pd":
        if not args.status:
            logging.error("Port deception ('pd') requires a '--status' argument. Exiting...")
            sys.exit(1)
        logging.info(f"Executing port deception with status {args.status}...")
        deceiver = PortDeceiver(args.host)
        deceiver.deceive_ps_hs(args.status)

    # Final validation before exiting
    if deceiver is None:
        logging.error("Deception failed. No valid technique was executed.")
        sys.exit(1)

    logging.info("Deception process completed successfully.")

if __name__ == "__main__":
    main()
