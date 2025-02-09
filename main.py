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

    settings.host = args.host

    if args.nic:
        settings.NIC = args.nic

    if args.scan:  # <-- FIXED INDENTATION HERE
        port_scan_tech = args.scan

        if port_scan_tech == 'ts':
            deceiver = OsDeceiver(args.host, args.os)
            deceiver.os_record()
        elif port_scan_tech == 'od':
            if args.os is None:
                logging.debug('No os is designated')
            else:
                deceiver = OsDeceiver(args.host, args.os)
                deceiver.os_deceive()
        elif port_scan_tech == 'rr':
            deceiver = OsDeceiver(args.host, args.os)
            deceiver.store_rsp()

        if args.status:
            deceive_status = args.status
            if port_scan_tech == 'pd':
                deceiver = PortDeceiver(args.host)
                deceiver.deceive_ps_hs(deceive_status)

        else:
            logging.debug('No port scan technique is designated')
            return

    else:
        logging.debug('No scan technique is designated')
        return


if __name__ == '__main__':
    main()
