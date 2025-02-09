import os
import argparse
import logging
import sys
import socket
import struct
import src.settings as settings
from src.Packet import Packet
from src.tcp import TcpConnect
from src.port_deceiver import PortDeceiver
from src.os_deceiver import OsDeceiver

def main():
    parser = argparse.ArgumentParser(description="Deceiver Demo")
    parser.add_argument("--host", required=True, help="Specify destination IP")
    parser.add_argument("--port", action="store", help="Specify destination port")
    parser.add_argument("--nic", required=True, help="NIC where we capture the packets")
    parser.add_argument("--scan", required=True, help="Attacker's port scanning technique")
    parser.add_argument("--status", action="store", help="Designate port status")
    parser.add_argument("--os", action="store", help="Designate OS we want to deceive (optional for ts)")
    args = parser.parse_args()

    if settings is not None:
        settings.HOST = args.host
        settings.NIC = args.nic
    else:
        logging.error("Settings module not found! Exiting...")
        sys.exit(1)

    if args.scan:
        port_scan_tech = args.scan.lower()

        if port_scan_tech == "ts":
            logging.info("Executing fingerprint capture (TS mode)...")
            deceiver = OsDeceiver(args.host, args.os)
            deceiver.os_record()
            logging.info("Fingerprint capture completed.")
            return

        elif port_scan_tech == "od":
            logging.info(f"Executing OS Deception on {args.host}, mimicking {args.os}...")
            if args.os is None:
                logging.warning("No OS specified for deception.")
            else:
                deceiver = OsDeceiver(args.host, args.os)
                if hasattr(deceiver, 'os_deceive') and callable(getattr(deceiver, 'os_deceive')):
                    logging.info("Starting OS deception...")
                    try:
                        deceiver.os_deceive()
                    except Exception as e:
                        logging.error(f"Error in os_deceive(): {e}")
                        sys.exit(1)
                else:
                    logging.error("os_deceive() function is missing or not callable in OsDeceiver!")
                    sys.exit(1)

        elif port_scan_tech == "rr":
            logging.info("Recording response packets...")
            deceiver = OsDeceiver(args.host, args.os)
            deceiver.store_rsp()

        elif port_scan_tech == "pd":
            if args.status:
                deceive_status = args.status
                logging.info(f"Executing Port Deception (status: {deceive_status})...")
                deceiver = PortDeceiver(args.host)
                deceiver.deceive_ps_hs(deceive_status)
            else:
                logging.warning("No port status specified for 'pd' technique.")

        else:
            logging.error("Invalid scan technique provided!")

    else:
        logging.warning("No scan technique specified!")

if __name__ == "__main__":
    logging.basicConfig(
        format='%(asctime)s [%(levelname)s]: %(message)s',
        datefmt='%y-%m-%d %H:%M',
        level=logging.INFO
    )
    main()
    #
