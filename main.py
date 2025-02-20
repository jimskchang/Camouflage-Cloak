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
    parser.add_argument("--host", required=True, help="Target host IP to deceive or fingerprint (e.g., 192.168.23.201)")
    parser.add_argument("--nic", required=True, help="Network interface to capture packets (e.g., ens192)")
    parser.add_argument("--scan", required=True, choices=["ts"], help="Scanning technique [ts: fingerprinting]")
    parser.add_argument("--dest", help="Directory to store captured fingerprints for ts mode")
    parser.add_argument("--od", action="store_true", help="Enable OS deception mode")
    parser.add_argument("--os", help="The OS to mimic in od mode (e.g., win10, centos)", required=False)
    parser.add_argument("--status", help="Designate port status for 'pd' (Port Deception) mode")

    args = parser.parse_args()

    # Ensure --os is not required when --scan ts is used
    if args.scan == "ts" and args.os:
        logging.error("--os should not be used with --scan ts mode")
        sys.exit(1)

    if args.od and not args.os:
        logging.error("--os argument is required for od mode")
        sys.exit(1)

    # Ensure network interface is in promiscuous mode
    logging.info(f"Setting {args.nic} to promiscuous mode...")
    os.system(f"sudo ip link set {args.nic} promisc on")

    # Verify settings are properly configured
    if settings is not None:
        settings.HOST = args.host
        settings.NIC = args.nic
        if args.scan == "ts":
            settings.OUTPUT_DIR = args.dest
    else:
        logging.error("Settings module not found! Exiting...")
        sys.exit(1)

    # Determine the mode of operation
    if args.scan == "ts":
        if not args.dest:
            logging.error("--dest argument is required for ts mode")
            sys.exit(1)
        logging.info(f"Executing OS Fingerprinting on {args.host} (Max: 100 packets, Timeout: 2 min)...")
        deceiver = OsDeceiver(target_host=args.host, target_os="unknown")  # OS mimicry not needed
        deceiver.os_record(max_packets=100)
        logging.info("Fingerprinting completed.")
        return  # Exit after capturing

    if args.od:
        logging.info(f"Executing OS Deception on {args.host}, mimicking {args.os}...")
        deceiver = OsDeceiver(target_host=args.host, target_os=args.os)
        if hasattr(deceiver, "os_deceive"):
            try:
                deceiver.os_deceive()
            except Exception as e:
                logging.error(f"[OS Deception] Error in os_deceive(): {e}")
                sys.exit(1)
        else:
            logging.error("Method os_deceive() not implemented in OsDeceiver class.")
            sys.exit(1)

if __name__ == "__main__":
    logging.basicConfig(
        format="%(asctime)s [%(levelname)s]: %(message)s",
        datefmt="%y-%m-%d %H:%M",
        level=logging.DEBUG  # Enable debug logging
    )
    main()
