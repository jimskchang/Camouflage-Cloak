import logging
import argparse
import src.settings as settings
from src.port_deceiver import PortDeceiver
from src.os_deceiver import OsDeceiver

# Configure Logging
logging.basicConfig(
    format='%(asctime)s [%(levelname)s]: %(message)s',
    datefmt='%y-%m-%d %H:%M',
    level=logging.INFO
)

def main():
    parser = argparse.ArgumentParser(description='Deceiver Demo')
    parser.add_argument('--host', action="store", required=True, help='Specify destination IP')
    parser.add_argument('--port', action="store", type=int, help='Specify destination port')
    parser.add_argument('--nic', action="store", help='NIC where we capture the packets')
    parser.add_argument('--scan', action="store", required=True, choices=["ts", "od", "rr", "pd"], help='Attacker's port scanning technique')
    parser.add_argument('--status', action="store", choices=["open", "close"], help='Designate port status')
    parser.add_argument('--os', action="store", required=True, help='Designate OS we want to deceive')
    parser.add_argument('--output-dir', action="store", default=settings.RECORDS_FOLDER, help='Specify base directory to save OS records')
    
    args = parser.parse_args()
    settings.host = args.host

    if args.nic:
        settings.NIC = args.nic

    port_scan_tech = args.scan.lower() if args.scan else None

    if port_scan_tech:
        if port_scan_tech == 'ts':
            logging.info(f"Starting OS deception and recording packets for {args.host}...")
            deceiver = OsDeceiver(args.host, args.os)
            deceiver.os_record()
        elif port_scan_tech == 'od':
            if not args.os:
                logging.error('No OS is designated')
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
            logging.error('No port scan technique is designated')
            return
    else:
        logging.error('No scan technique is designated')
        return

if __name__ == '__main__':
    main()
