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
    parser.add_argument('--dest', required=True, help='Designate folder to store logs')

    args = parser.parse_args()

    settings.host = args.host
    settings.NIC = args.nic

    # Create the deceiver object based on parameters
    deceiver = OsDeceiver(args.host, args.os)  # Initialize with os as is (may be None)

    if args.scan:
        port_scan_tech = args.scan

        if port_scan_tech == 'ts':
            # For ts scan, proceed without needing a valid OS name
            if deceiver:
                deceiver.os_record(output_path=args.dest)  
            else:
                logging.error('Failed to create OsDeceiver for ts scan.')
        elif port_scan_tech == 'od':
            if deceiver:
                deceiver.os_deceive()
            else:
                logging.debug('No OS is designated for od scan.')
        elif port_scan_tech == 'rr':
            if deceiver:
                deceiver.store_rsp()
        elif port_scan_tech == 'pd':
            if args.status:
                deceive_status = args.status
                port_deceiver = PortDeceiver(args.host)
                port_deceiver.deceive_ps_hs(deceive_status)
            else:
                logging.debug('No port status designated for PD scan.')
        else:
            logging.debug('No valid scan technique is designated.')

if __name__ == '__main__':
    main()
