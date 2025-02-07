import logging
import argparse
import os
import sys
from src import settings
from src  import port_deceiver
from src import os_deceiver

logging.basicConfig(
    format='%(asctime)s [%(levelname)s]: %(message)s',
    datefmt='%y-%m-%d %H:%M',
    level=logging.INFO
)

def main():
    parser = argparse.ArgumentParser(description='Deceiver Demo')
    parser.add_argument('--host', action="store", required=True, help='Specify destination IP')
    parser.add_argument('--port', action="store", help='Specify destination port')
    parser.add_argument('--nic', action="store", required=True, help='NIC where we capture the packets')
    parser.add_argument('--scan', action="store", required=True, help="Attacker's port scanning technique")
    parser.add_argument('--status', action="store", help='Designate port status')
    parser.add_argument('--os', action="store", help='Designate OS we want to deceive')
    parser.add_argument('--dest', action="store", help='Specify file storage location')    

    args = parser.parse_args()
    settings.host = args.host
    settings.NIC = args.nic

    if args.dest:
        os_record_dir = settings.get_os_record_dir(args.dest)
    else:
        os_record_dir = settings.TARGET_OS_OUTPUT_DIR
    
    if not os.path.exists(os_record_dir):
        logging.info(f"Creating output directory: {os_record_dir}")
        os.makedirs(os_record_dir, exist_ok=True)
    
    port_scan_tech = args.scan

    if port_scan_tech == 'ts':
        deceiver = OsDeceiver(args.host, args.os)
        deceiver.os_record(output_path=os_record_dir)
    elif port_scan_tech == 'od':
        if args.os is None:
            logging.debug('No OS is designated')
        else:
            deceiver = OsDeceiver(args.host, args.os)
            deceiver.os_deceive(output_path=os_record_dir)
    elif port_scan_tech == 'rr':
        deceiver = OsDeceiver(args.host, args.os)
        deceiver.store_rsp(output_path=os_record_dir)
    elif port_scan_tech == 'pd':
        if args.status:
            deceiver = PortDeceiver(args.host)
            deceiver.deceive_ps_hs(args.status, output_path=os_record_dir)
        else:
            logging.error('Port status must be specified for PD scan')
            return
    else:
        logging.error('Invalid port scan technique specified')
        return

if __name__ == '__main__':
    main()
