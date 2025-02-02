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
    parser.add_argument('--output-dir', action="store", help='Specify output directory for storing records')

    args = parser.parse_args()

    # Ensure a host is provided
    if not args.host:
        logging.error("ERROR: --host is required for --scan ts")
        return

    # Ensure an output directory is provided for --scan ts
    if args.scan == "ts" and not args.output_dir:
        logging.error("ERROR: --output-dir is required for --scan ts")
        return

    # Assign settings values
    settings.TARGET_HOST = args.host
    if args.nic:
        settings.CLOAK_NIC = args.nic

    # Default to settings.TS_SERVER_OS if --os is not provided
    args.os = args.os or settings.TS_SERVER_OS

    # Ensure output directory exists
    if args.output_dir:
        os.makedirs(args.output_dir, exist_ok=True)

    # Execute based on the selected scanning technique
    if args.scan:
        port_scan_tech = args.scan.lower()

        if port_scan_tech == 'ts':
            logging.info(f"Executing TS scan on {args.host}, storing results in {args.output_dir}")
            deceiver = OsDeceiver(args.host, args.os)
            deceiver.os_record(output_path=args.output_dir)

        elif port_scan_tech == 'od':
            if not args.os:
                logging.error("No OS specified for OS deception.")
                return
            logging.info(f"Executing OS deception for {args.host} using {args.os}")
            deceiver = OsDeceiver(args.host, args.os)
            deceiver.os_deceive(output_path=args.output_dir)

        elif port_scan_tech == 'rr':
            logging.info(f"Recording responses from {args.host}")
            deceiver = OsDeceiver(args.host, args.os)
            deceiver.store_rsp(output_path=args.output_dir)

        elif port_scan_tech == 'pd':
            if not args.status:
                logging.error("Port status must be specified for 'pd' scan")
                return
            logging.info(f"Executing Port Deception for {args.host} with status {args.status}")
            deceiver = PortDeceiver(args.host)
            deceiver.deceive_ps_hs(args.status, output_path=args.output_dir)

        else:
            logging.error("Invalid port scan technique specified.")
            return

    else:
        logging.error("No scan technique specified.")
        return


if __name__ == '__main__':
    main()
