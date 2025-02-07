import logging
import argparse
import src.settings as settings
from src.port_deceiver import PortDeceiver
from src.os_deceiver import OsDeceiver


logging.basicConfig(
    format='%(asctime)s [%(levelname)s]: %(message%',
    datefmt='%y-%m-%d %H:%M',
    level=logging.INFO
)


def main():
    parser = argparse.ArgumentParser(description='Deceiver Demo')
    parser.add_argument('--host', action="store", help='specify destination ip')
    parser.add_argument('--port', action="store", help='specify destination port')
    parser.add_argument('--nic', action="store", help='nic where we capture the packets')
    parser.add_argument('--scan', action="store", help='attacker\'s port scanning technique')
    parser.add_argument('--status', action="store", help='designate port status')
    parser.add_argument('--os', action="store", help='designate os we want to deceive')
    parser.add_argument('--dest', action="store", help='Specify output directory for storing OS records')
    args = parser.parse_args()
    settings.host = args.host

    if args.nic:
        settings.NIC = args.nic

    if args.scan:
        port_scan_tech = args.scan

        os_record_dir = settings.get_os_record_dir(args.dest)

        if port_scan_tech == 'ts':
            logging.info(f"Executing TS scan on {args.host}, storing results in {os_record_dir}")
            deceiver = OsDeceiver(args.host, args.os)
            deceiver.os_record(output_path=os_record_dir)
        elif port_scan_tech == 'od':
            if args.os is None:
                logging.debug('No os is designated')
            else:
                logging.info(f"Executing OS deception for {args.host} using {args.os}, storing results in {os_record_dir}")
                deceiver = OsDeceiver(args.host, args.os)
                deceiver.os_deceive(output_path=os_record_dir)
        elif port_scan_tech == 'rr':
            logging.info(f"Recording responses from {args.host}, storing results in {os_record_dir}")
            deceiver = OsDeceiver(args.host, args.os)
            deceiver.store_rsp(output_path=os_record_dir)

        if args.status:
            deceive_status = args.status
            if port_scan_tech == 'pd':
                logging.info(f"Executing Port Deception for {args.host} with status {deceive_status}, storing results in {os_record_dir}")
                deceiver = PortDeceiver(args.host)
                deceiver.deceive_ps_hs(deceive_status, output_path=os_record_dir)

        else:
            logging.debug('No port scan technique is designated')
            return

    else:
        logging.debug('No scan technique is designated')
        return


if __name__ == '__main__':
    main()
