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
    parser = argparse.ArgumentParser(description="Camouflage Cloak - OS Deception & Fingerprinting System")
    parser.add_argument("--host", required=True, help="Target host IP to deceive (e.g., 192.168.23.201)")
    parser.add_argument("--nic", required=True, help="Network interface to capture packets (e.g., ens192)")
    parser.add_argument("--scan", required=True, help="Scanning technique [ts: fingerprinting, od: deception]")
    parser.add_argument("--status", help="Designate port status for 'pd' (Port Deception) mode")
    parser.add_argument("--os", required=True, help="The OS to mimic (e.g., win10, centos)")

    args = parser.parse_args()

    # Ensure network interface is in promiscuous mode
    logging.info(f"Setting {args.nic} to promiscuous mode...")
    os.system(f"sudo ip link set {args.nic} promisc on")

    # Verify settings are properly configured
    if settings is not None:
        settings.HOST = args.host
        settings.NIC = args.nic
    else:
        logging.error("Settings module not found! Exiting...")
        sys.exit(1)

    # Initialize OsDeceiver with correct arguments
    try:
        deceiver = OsDeceiver(target_host=args.host, target_os=args.os)
        logging.info(f"OsDeceiver initialized for {args.host}, mimicking {args.os}")
    except TypeError as e:
        logging.error(f"Error initializing OsDeceiver: {e}")
        sys.exit(1)

    # Determine the mode of operation
    port_scan_tech = args.scan.lower()

    if port_scan_tech == "ts":
        logging.info(f"Executing OS Fingerprinting on {args.host} (Max: 100 packets, Timeout: 2 min)...")
        deceiver.os_record(max_packets=100)
        logging.info("Fingerprinting completed.")
        return  # Exit after capturing

    elif port_scan_tech == "od":
        logging.info(f"Executing OS Deception on {args.host}, mimicking {args.os}...")
        if hasattr(deceiver, "os_deceive"):
            try:
                deceiver.os_deceive()
            except Exception as e:
                logging.error(f"[OS Deception] Error in os_deceive(): {e}")
                sys.exit(1)
        else:
            logging.error("Method os_deceive() not implemented in OsDeceiver class.")
            sys.exit(1)

    elif port_scan_tech == "rr":
        logging.info("Recording response packets...")
        if hasattr(deceiver, "store_rsp"):
            try:
                deceiver.store_rsp()
            except Exception as e:
                logging.error(f"Error in store_rsp(): {e}")
                sys.exit(1)
        else:
            logging.error("Method store_rsp() not implemented in OsDeceiver class.")
            sys.exit(1)

    elif port_scan_tech == "pd":
        if args.status:
            deceive_status = args.status
            logging.info(f"Executing Port Deception (status: {deceive_status})...")
            try:
                port_deceiver = PortDeceiver(args.host)
                port_deceiver.deceive_ps_hs(deceive_status)
            except Exception as e:
                logging.error(f"Error in Port Deception: {e}")
                sys.exit(1)
        else:
            logging.warning("No port status specified for 'pd' technique.")

    else:
        logging.error("Invalid scan technique provided!")
        sys.exit(1)

if __name__ == "__main__":
    logging.basicConfig(
        format="%(asctime)s [%(levelname)s]: %(message)s",
        datefmt="%y-%m-%d %H:%M",
        level=logging.DEBUG  # Enable debug logging
    )
    main()

