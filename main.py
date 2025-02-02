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
    parser = argparse.ArgumentParser(description='Camouflage Cloak - Main Execution')
    parser.add_argument('--host', action="store", required=True, help='Specify destination IP')
    parser.add_argument('--port', action="store", help='Specify destination port')
    parser.add_argument('--nic', action="store", help='NIC where we capture the packets')
    parser.add_argument('--scan', action="store", required=True, help="Attacker's port scanning technique")
    parser.add_argument('--status', action="store", help='Designate port status')
    parser.add_argument('--os', action="store", help='Designate OS we want to deceive')
    parser.add_argument('--output-dir', action="store", help='Specify output directory for storing records')

    args = parser.parse_args()

    # Assign local variables without modifying settings.py
    target_host = args.host
    output_dir = args.output_dir if args.output_dir else settings.TS_OS_OUTPUT_DIR
    os_type = args.os if args.os else settings.TS_SERVER_OS
    scan_type = args.scan.lower() if args.scan else None

    # Ensure output directory exists
    os.makedirs(output_dir, exist_ok=True)

    # Log configuration
    logging.info(f"Configuration: Target Host={target_host}, OS={os_type}, Output Dir={output_dir}")

    # Execute based on the selected scanning technique
    if scan_type == 'ts':
        logging.info(f"Executing TS scan on {target_host}, storing results in {output_dir}")
        deceiver = OsDeceiver(target_host, os_type)
        deceiver.os_record(output_path=output_dir)

    elif scan_type == 'od':
        logging.info(f"Executing OS deception for {target_host} using {os_type}")
        deceiver = OsDeceiver(target_host, os_type)
        deceiver.os_deceive(output_path=output_dir)

    elif scan_type == 'rr':
        logging.info(f"Recording responses from {target_host}")
        deceiver = OsDeceiver(target_host, os_type)
        deceiver.store_rsp(output_path=output_dir)

    elif scan_type == 'pd':
        if not args.status:
            logging.error("Port status must be specified for 'pd' scan")
            return
        logging.info(f"Executing Port Deception for {target_host} with status {args.status}")
        deceiver = PortDeceiver(target_host)
        deceiver.deceive_ps_hs(args.status, output_path=output_dir)

    else:
        logging.error("Invalid port scan technique specified.")
        return


if __name__ == '__main__':
    main()
