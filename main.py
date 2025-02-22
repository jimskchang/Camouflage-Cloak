import os
import argparse
import logging
import sys
import threading
import src.settings as settings
from src.os_deceiver import OsDeceiver
from src.port_deceiver import PortDeceiver

# Global references to deceiver instances
active_os_deceiver = None
active_port_deceiver = None

def disable_deception():
    """Stops OS and Port Deception after the specified duration."""
    global active_os_deceiver, active_port_deceiver

    if active_os_deceiver:
        logging.info("Stopping OS Deception...")
        try:
            active_os_deceiver.stop()
            logging.info("OS Deception successfully stopped.")
        except Exception as e:
            logging.error(f"Error stopping OS Deception: {e}")

    if active_port_deceiver:
        logging.info("Stopping Port Deception...")
        try:
            active_port_deceiver.stop()
            logging.info("Port Deception successfully stopped.")
        except Exception as e:
            logging.error(f"Error stopping Port Deception: {e}")

def validate_os_fingerprint(dest, os_name):
    """Check if OS fingerprint data exists before enabling deception."""
    os_path = dest if os.path.basename(dest) == os_name else os.path.join(dest, os_name)
    logging.debug(f"Validating OS fingerprint in path: {os_path}")
    
    if not os.path.exists(os_path):
        logging.error(f"OS fingerprint for '{os_name}' not found in '{dest}'.")
        logging.error(f"Please run '--scan ts' and store the fingerprint in '{dest}' first.")
        sys.exit(1)

def validate_port_fingerprint(dest, port_status):
    """Check if port fingerprint data exists before enabling deception."""
    port_path = os.path.join(dest, f"port_{port_status}")
    logging.debug(f"Validating port fingerprint in path: {port_path}")
    
    if not os.path.exists(port_path):
        logging.error(f"Port deception data for '{port_status}' not found in '{dest}'.")
        logging.error(f"Run '--scan ts' first to collect port fingerprinting data.")
        sys.exit(1)

def main():
    global active_os_deceiver, active_port_deceiver

    parser = argparse.ArgumentParser(description="Camouflage Cloak - OS Deception & Fingerprinting System")
    parser.add_argument("--host", required=True, help="Target host IP to deceive or fingerprint (e.g., 192.168.23.201)")
    parser.add_argument("--nic", required=True, help="Network interface to capture packets (e.g., ens192)")
    parser.add_argument("--scan", choices=["ts"], help="Scanning technique [ts: fingerprinting]")
    parser.add_argument("--dest", type=str, required=False, help="Directory to store captured fingerprints for ts mode")
    parser.add_argument("--od", action="store_true", help="Enable OS deception mode")
    parser.add_argument("--os", help="The OS to mimic in od mode (e.g., win10, centos)", required=False)
    parser.add_argument("--pd", action="store_true", help="Enable Port Deception mode")
    parser.add_argument("--status", help="Designate port status for 'pd' (Port Deception) mode (open/close)")
    parser.add_argument("--time", type=int, help="Duration (in minutes) for deception mode")

    args = parser.parse_args()

    if args.scan == "ts" and args.os:
        logging.error("--os should not be used with --scan ts mode")
        sys.exit(1)

    if (args.od or args.pd) and args.time is None:
        logging.error("--time argument is required when --od or --pd is enabled")
        sys.exit(1)
    
    if args.time and args.time <= 0:
        logging.error("--time must be a positive integer")
        sys.exit(1)

    if args.od:
        if not args.os:
            logging.error("--os argument is required for --od mode")
            sys.exit(1)
        if not args.dest:
            logging.error("--dest argument is required to validate OS fingerprints")
            sys.exit(1)
        validate_os_fingerprint(args.dest, args.os)

    if args.pd:
        if not args.status:
            logging.error("--status argument is required for --pd mode (open/close)")
            sys.exit(1)
        if not args.dest:
            logging.error("--dest argument is required to validate port fingerprints")
            sys.exit(1)
        validate_port_fingerprint(args.dest, args.status)

    logging.info(f"Setting {args.nic} to promiscuous mode...")
    os.system(f"sudo ip link set {args.nic} promisc on")

    if settings is not None:
        settings.HOST = args.host
        settings.NIC = args.nic
        if args.scan == "ts":
            settings.OUTPUT_DIR = args.dest
    else:
        logging.error("Settings module not found! Exiting...")
        sys.exit(1)

    if args.scan == "ts":
        if not args.dest:
            logging.error("--dest argument is required for ts mode")
            sys.exit(1)
        logging.info(f"Executing OS Fingerprinting on {args.host}...")
        deceiver = OsDeceiver(target_host=args.host, target_os="unknown", dest=args.dest, mode="scan")
        deceiver.os_record(max_packets=100)
        logging.info("Fingerprinting completed.")
        return

    if args.od:
        logging.info(f"Executing OS Deception on {args.host}, mimicking {args.os} for {args.time} minutes...")
        active_os_deceiver = OsDeceiver(target_host=args.host, target_os=args.os, dest=args.dest, mode="deception")
        try:
            active_os_deceiver.os_deceive()
        except Exception as e:
            logging.error(f"[OS Deception] Error: {e}")
            sys.exit(1)

    if args.pd:
        logging.info(f"Executing Port Deception on {args.host} for {args.time} minutes...")
        active_port_deceiver = PortDeceiver(target_host=args.host, port_status=args.status, dest=args.dest)
        try:
            active_port_deceiver.port_deceive()
        except Exception as e:
            logging.error(f"[Port Deception] Error: {e}")
            sys.exit(1)

    if args.od or args.pd:
        timer = threading.Timer(args.time * 60, disable_deception)
        timer.start()

if __name__ == "__main__":
    logging.basicConfig(format="%(asctime)s [%(levelname)s]: %(message)s", datefmt="%y-%m-%d %H:%M", level=logging.DEBUG)
    main()

