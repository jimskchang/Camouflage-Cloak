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
    logging.warning("Failed to import settings.py. Using default values.")
    settings = None

from src.port_deceiver import PortDeceiver
from src.os_deceiver import OsDeceiver

logging.basicConfig(
    format='%(asctime)s [%(levelname)s]: %(message)s',
    datefmt='%y-%m-%d %H:%M',
    level=logging.INFO
)

def main():
    parser = argparse.ArgumentParser(description='Deceiver Demo')
    parser.add_argument('--host', required=True, help='Specify destination IP')
    parser.add_argument('--port', action="store", help='Specify destination port')
    parser.add_argument('--nic', required=True, help='NIC where we capture the packets')
    parser.add_argument('--scan', required=True, help='Attacker\'s port scanning technique')
    parser.add_argument('--status', action="store", help='Designate port status')
    parser.add_argument('--os', action="store", help='Designate OS we want to deceive (optional for ts)')
    args = parser.parse_args()

    if settings is not None:  # Ensure settings is imported
        settings.HOST = args.host
        settings.NIC = args.nic
    else:
        logging.error("Settings module not found! Exiting...")
        sys.exit(1)

    if args.scan:
        port_scan_tech = args.scan
        deceiver = None  # Initialize to avoid undefined variable errors

        if port_scan_tech == 'ts':
            deceiver = OsDeceiver(args.host, args.os)
            deceiver.os_record()
        elif port_scan_tech == 'od':
            if args.os is None:
                logging.debug('No OS is designated')
            else:
                deceiver = OsDeceiver(args.host, args.os)
                deceiver.os_deceive()
        elif port_scan_tech == 'rr':
            deceiver = OsDeceiver(args.host, args.os)
            deceiver.store_rsp()
        elif port_scan_tech == 'pd':
            if args.status:
                deceive_status = args.status
                deceiver = PortDeceiver(args.host)
                deceiver.deceive_ps_hs(deceive_status)
            else:
                logging.debug("No port status specified for 'pd' technique")

        if deceiver is None:
            logging.debug("No valid port scan technique provided")

    else:
        logging.debug('No scan technique is designated')


if __name__ == '__main__':
    main()
