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
    parser.add_argument('--host', action="store", help='specify destination ip')
    parser.add_argument('--port', action="store", help='specify destination port')
    parser.add_argument('--nic', action="store", help='NIC where we capture the packets')
    parser.add_argument('--scan', action="store", help='Attacker\'s port scanning technique')
    parser.add_argument('--status', action="store", help='Designate port status')
    parser.add_argument('--os', action="store", help='Designate OS we want to deceive')
    parser.add_argument('--output-dir', action="store", help='Directory where we store the record')
    parser.add_argument('--dest', action="store", help='Filename to store the record')

    args = parser.parse_args()
    settings.host = args.host

    if args.nic:
        settings.NIC = args.nic

    if args.output_dir and args.dest:
        # Ensure the directory exists
        os.makedirs(args.output_dir, exist_ok=True)
        output_path = os.path.join(args.output_dir, args.dest)
    else:
        logging.warning("Both --output-dir and --dest must be provided to store records.")
        output_path = None

    if args.scan:
        port_scan_tech = args.scan

        if port_scan_tech == 'ts':
            deceiver = OsDeceiver(args.host, args.os)
            deceiver.os_record(output_path)
        elif port_scan_tech == 'od':
            if args.os is None:
                logging.debug('No OS is designated')
            else:
                deceiver = OsDeceiver(args.host, args.os)
                deceiver.os_deceive(output_path)
        elif port_scan_tech == 'rr':
            deceiver = OsDeceiver(args.host, args.os)
            deceiver.store_rsp(output_path)

        if args.status:
            deceive_status = args.status
            if port_scan_tech == 'pd':
                deceiver = PortDeceiver(args.host)
                deceiver.deceive_ps_hs(deceive_status, output_path)

        else:
            logging.debug('No port scan technique is designated')
            return

    else:
        logging.debug('No scan technique is designated')
        return


if __name__ == '__main__':
    main()
