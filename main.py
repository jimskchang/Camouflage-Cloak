import logging
import argparse
import os
import threading
import src.settings as settings
from src.port_deceiver import PortDeceiver
from src.os_deceiver import OsDeceiver

# Logging configuration
logging.basicConfig(
    format='%(asctime)s [%(levelname)s]: %(message)s',
    datefmt='%y-%m-%d %H:%M',
    level=logging.INFO
)

def main():
    parser = argparse.ArgumentParser(description='Deceiver Demo')
    parser.add_argument('--host', required=True, help='Specify destination IP')
    parser.add_argument('--port', help='Specify destination port')
    parser.add_argument('--nic', required=True, help='NIC where we capture the packets')
    parser.add_argument('--scan', choices=['ts', 'od', 'rr', 'pd'], required=True, help='Attacker\'s port scanning technique')
    parser.add_argument('--status', help='Designate port status (used with --scan pd)')
    parser.add_argument('--os', help='Designate OS we want to deceive (required for --scan od)')
    parser.add_argument('--dest', required=True, help='Directory to store OS fingerprints')
    parser.add_argument('--te', type=int, help='Timeout duration in minutes for --od and --pd (e.g., --te 6 for 6 minutes)')
    
    args = parser.parse_args()
    
    settings.HOST = args.host
    settings.NIC = args.nic

    # Ensure destination directory exists
    if not os.path.exists(args.dest):
        os.makedirs(args.dest)
    
    logging.info(f"Starting deception tool with mode: {args.scan}")

    if args.scan == 'ts':
        logging.info(f"Executing OS Fingerprinting for {args.host}...")
        deceiver = OsDeceiver(args.host, "unknown", dest=args.dest)  # Store in unknown by default
        deceiver.os_record()
        logging.info(f"Fingerprinting completed. Data stored in {args.dest}")
    
    elif args.scan == 'od':
        if not args.os:
            logging.error("Missing required argument: --os is needed for --scan od")
            return
        if not args.te:
            logging.error("Missing required argument: --te is needed for --scan od")
            return
        logging.info(f"Executing OS Deception on {args.host}, mimicking {args.os}...")
        deceiver = OsDeceiver(args.host, args.os, dest=args.dest)
        deceiver.os_deceive()
        logging.info(f"OS Deception will run for {args.te} minutes...")
        timer = threading.Timer(args.te * 60, deceiver.stop)
        timer.start()
    
    elif args.scan == 'rr':
        logging.info(f"Storing OS response fingerprint for {args.host} in {args.dest}...")
        deceiver = OsDeceiver(args.host, "unknown", dest=args.dest)  
        deceiver.store_rsp()
        logging.info("OS response stored.")
    
    elif args.scan == 'pd':
        if not args.status:
            logging.error("Missing required argument: --status is needed for --scan pd")
            return
        if not args.te:
            logging.error("Missing required argument: --te is needed for --scan pd")
            return
        logging.info(f"Executing Port Deception on {args.host}, setting ports to {args.status}...")
        deceiver = PortDeceiver(args.host)
        deceiver.deceive_ps_hs(args.status)
        logging.info(f"Port Deception will run for {args.te} minutes...")
        timer = threading.Timer(args.te * 60, deceiver.stop)
        timer.start()
    
    else:
        logging.error("Invalid scan technique specified.")
        return

if __name__ == '__main__':
    main()
