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
    parser.add_argument("--os", dest="target_os", action="store", help="Designate OS we want to deceive (optional for ts)")
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
            logging.info(f"[TS Mode] Capturing fingerprinting packets for {args.host}...")
            deceiver = OsDeceiver(args.host, args.target_os or "unknown_os")
            deceiver.os_record()
            logging.info("[TS Mode] Fingerprint capture completed.")
            return

        elif port_scan_tech == "od":
            if not args.target_os:
                logging.warning("No OS specified for deception. Please provide an OS using --os.")
                sys.exit(1)

            logging.info(f"[OS Deception] Targeting {args.host}, mimicking {args.target_os}...")
            deceiver = OsDeceiver(args.host, args.target_os)

            # Ensure os_deceive() exists before calling
            os_deceive_func = getattr(deceiver, "os_deceive", None)
            if callable(os_deceive_func):
                try:
                    logging.info("[OS Deception] Starting deception process...")
                    os_deceive_func()
                except Exception as e:
                    logging.error(f"[OS Deception] Error in os_deceive(): {e}")
                    sys.exit(1)
            else:
                logging.error("[OS Deception] os_deceive() function is missing or not callable!")
                sys.exit(1)

        elif port_scan_tech == "rr":
            logging.info(f"[Response Recording] Capturing response packets from {args.host}...")
            deceiver = OsDeceiver(args.host, args.target_os or "unknown_os")
            deceiver.store_rsp()
            logging.info("[Response Recording] Packet capture complete.")

        elif port_scan_tech == "pd":
            if args.status:
                logging.info(f"[Port Deception] Deceiving port status: {args.status} on {args.host}...")
                deceiver = PortDeceiver(args.host)
                deceiver.deceive_ps_hs(args.status)
            else:
                logging.warning("[Port Deception] No port status specified! Use --status open/close.")

        else:
            logging.error(f"[ERROR] Invalid scan technique: {port_scan_tech}")

    else:
        logging.warning("[WARNING] No scan technique specified! Use --scan [ts|od|rr|pd]")

if __name__ == "__main__":
    logging.basicConfig(
        format='%(asctime)s [%(levelname)s]: %(message)s',
        datefmt='%y-%m-%d %H:%M',
        level=logging.INFO
    )
    main()
