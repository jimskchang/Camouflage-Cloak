import argparse
import os
import logging
import src.settings as settings
from src.PortDeceiver import PortDeceiver
from src.OsDeceiver import OsDeceiver

def main():
    # Set up argument parser
    parser = argparse.ArgumentParser(description="Camouflage-Cloak main program")
    parser.add_argument("-s", "--scan", choices=["od", "pd", "ts"], required=True,
                        help="Scan mode: 'od' (OS deception), 'pd' (Port deception), 'ts' (template synthesis)")
    parser.add_argument("-t", "--te", help="Target environment identifier/IP (required for 'od' or 'pd' modes)")
    parser.add_argument("-d", "--dest", default="/home/user/Camouflage-Cloak/os_record/",
                        help="Destination directory for OS fingerprint records")
    args = parser.parse_args()

    # Enforce that --te is provided when using --scan od or pd
    if args.scan in ["od", "pd"] and args.te is None:
        parser.error("--te is a required argument when using --scan 'od' or 'pd'")

    # Load NIC, HOST, and MAC settings from settings.py
    NIC = settings.NIC
    HOST = settings.HOST
    MAC = settings.MAC

    # Ensure destination directory exists
    dest_dir = args.dest
    try:
        os.makedirs(dest_dir, exist_ok=True)
    except Exception as e:
        logging.error(f"Could not create destination directory '{dest_dir}': {e}")
        return

    # Handle each scan mode
    if args.scan == "ts":
        # Maintain a 180-second timeout for template synthesis
        TIMEOUT = 180
        logging.info(f"Starting template synthesis for target environment '{args.te}' with {TIMEOUT}s timeout")

        # Open OS fingerprint record files (prevent locking by closing them after writing)
        arp_file = open(os.path.join(dest_dir, "arp_record.txt"), "w")
        icmp_file = open(os.path.join(dest_dir, "icmp_record.txt"), "w")
        tcp_file = open(os.path.join(dest_dir, "tcp_record.txt"), "w")
        udp_file = open(os.path.join(dest_dir, "udp_record.txt"), "w")
        try:
            # --- Existing template synthesis logic to gather OS fingerprint data (ARP, ICMP, TCP, UDP) goes here ---
            # For example:
            # arp_file.write(... data from ARP probe on target environment ...)
            # icmp_file.write(... data from ICMP probe on target environment ...)
            # tcp_file.write(... data from TCP probes on target environment ...)
            # udp_file.write(... data from UDP probe on target environment ...)
            pass  # (Placeholder for the existing scanning implementation)
        finally:
            # Close all files after writing to release any locks
            arp_file.close()
            icmp_file.close()
            tcp_file.close()
            udp_file.close()
            logging.info("Template synthesis complete. OS fingerprint records saved.")
    elif args.scan == "od":
        # Start OS deception mode (requires target environment template)
        logging.info(f"Starting OS deception using template for target environment '{args.te}'")
        try:
            od = OsDeceiver(NIC=NIC, host_ip=HOST, host_mac=MAC, dest=dest_dir, target_env=args.te)
        except TypeError:
            # Fallback if OsDeceiver expects positional arguments
            od = OsDeceiver(NIC, HOST, MAC, dest_dir, args.te)
        od.start()  # Begin OS deception (listening and responding to scans)
    elif args.scan == "pd":
        # Start Port deception mode (requires target environment template)
        logging.info(f"Starting Port deception using template for target environment '{args.te}'")
        try:
            pd = PortDeceiver(NIC=NIC, host_ip=HOST, host_mac=MAC, dest=dest_dir, target_env=args.te)
        except TypeError:
            pd = PortDeceiver(NIC, HOST, MAC, dest_dir, args.te)
        pd.start()  # Begin Port deception (listening and responding to port scans)

if __name__ == "__main__":
    main()
