import logging
import argparse
import os
import src.settings as settings
from src.port_deceiver import PortDeceiver
from src.os_deceiver import OsDeceiver

logging.basicConfig(
    format='%(asctime)s [%(levelname)s]: %(message)s',
    datefmt='%y-%m-%d %H:%M',
    level=logging.INFO
)

def main():
    parser = argparse.ArgumentParser(description='Deceiver Demo')
    parser.add_argument('--host', action="store", help='Specify destination IP')
    parser.add_argument('--port', action="store", help='Specify destination port')
    parser.add_argument('--nic', action="store", help='NIC where we capture the packets')
    parser.add_argument('--scan', action="store", help="Attacker's port scanning technique")
    parser.add_argument('--status', action="store", help='Designate port status')
    parser.add_argument('--os', action="store", help='Designate OS we want to deceive')
    parser.add_argument('--output-dir', action="store", help='Directory where we store the record')
    parser.add_argument('--dest', action="store", help='Filename to store the record')

    args = parser.parse_args()

    # Ensure a host is provided
    settings.TARGET_HOST = args.host or settings.TARGET_HOST

    # Ensure NIC is provided
    if args.nic:
        settings.CLOAK_NIC = args.nic

    # Default to settings.TS_SERVER_OS if --os is not provided
    args.os = args.os or settings.TS_SERVER_OS

    # Ensure --output-dir is set, otherwise default to settings.TS_OS_OUTPUT_DIR
    if args.output_dir:
        output_dir = args.output_dir
    else:
        logging.warning("No --output-dir provided, using default: %s", settings.TS_OS_OUTPUT_DIR)
        output_dir = settings.TS_OS_OUTPUT_DIR

    # Ensure the output directory exists
    os.makedirs(output_dir, exist_ok=True)

    # Ensure a valid filename is provided
    if args.dest:
        output_path = os.path.join(output_dir, args.dest)
    else:
        logging.warning("No --dest provided, data will not be saved.")
        output_path = None

    # Ensure a scan type is specified
    if args.scan:
        port_scan_tech = args.scan.lower()

        if port_scan_tech == 'ts':
            if not args.os:
                raise ValueError("ERROR: OS must be specified for TS scan")
            deceiver = OsDeceiver(args.host, args.os)
            deceiver.os_record(output_path)

        elif port_scan_tech == 'od':
            if not args.os:
                logging.error("No OS specified for OS deception.")
                return
            deceiver = OsDeceiver(args.host, args.os)
            deceiver.os_deceive(output_path)

        elif port_scan_tech == 'rr':
            deceiver = OsDeceiver(args.host, args.os)
            deceiver.store_rsp(output_path)

        elif port_scan_tech == 'pd':
            if not args.status:
                logging.error("Port status must be specified for 'pd' scan")
                return
            deceiver = PortDeceiver(args.host)
            deceiver.deceive_ps_hs(args.status, output_path)

        else:
            logging.error("Invalid port scan technique specified.")
            return

    else:
        logging.error("No scan technique specified.")
        return


if __name__ == '__main__':
    main()
