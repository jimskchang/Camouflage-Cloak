import logging
import argparse
import os  # Importing the os module
import src.settings as settings
from src.port_deceiver import PortDeceiver
from src.os_deceiver import OsDeceiver

# Configure Logging
log_dir = "logs"
if not os.path.exists(log_dir):
    os.makedirs(log_dir)
    logging.info(f"Created log directory: {log_dir}")

log_file_path = os.path.join(log_dir, 'deception.log')
logging.basicConfig(
    format="%(asctime)s [%(levelname)s]: %(message)s",
    datefmt="%y-%m-%d %H:%M",
    filename=log_file_path,
    level=logging.INFO,
)

def main():
    # Argument Parser
    parser = argparse.ArgumentParser(description="Camouflage Cloak - Deceiver Module")
    parser.add_argument("--host", required=True, help="Specify destination IP (required)")
    parser.add_argument("--port", type=int, help="Specify destination port")
    parser.add_argument("--nic", help="Specify network interface for packet capture")
    parser.add_argument("--scan", choices=["ts", "od", "rr", "pd"], help="Specify deception technique")
    parser.add_argument("--status", choices=["open", "close"], help="Set port status (only for pd)")
    parser.add_argument("--os", required=True, help="Specify OS to deceive")  # Now it's required
    parser.add_argument("--output-dir", default="/os_record", help="Base directory to save OS records")

    args = parser.parse_args()

    # Assign settings
    settings.host = args.host
    settings.NIC = args.nic if args.nic else "ens192"  # Default to vmxnet if not specified

    # Create the base output directory if it does not exist
    if not os.path.exists(args.output_dir):
        os.makedirs(args.output_dir)
        logging.info(f"Created base output directory: {args.output_dir}")

    # Create the OS-specific output directory
    os_output_dir = os.path.join(args.output_dir, args.os)
    if not os.path.exists(os_output_dir):
        os.makedirs(os_output_dir)
        logging.info(f"Created OS-specific output directory: {os_output_dir}")

    # Validate Required Arguments
    if not args.scan:
        logging.error("Error: No scan technique designated. Use --scan <technique>.")
        scan_input = input("Enter scan technique (ts, od, rr, pd): ").strip()
        if scan_input in ["ts", "od", "rr", "pd"]:
            args.scan = scan_input
        else:
            logging.error("Invalid input. Exiting.")
            return

    logging.info(f"Starting deception with technique: {args.scan}")

    try:
        # Handle OS Deception Techniques
        if args.scan in ["ts", "od", "rr"]:
            deceiver = OsDeceiver(args.host, args.os, os_output_dir)  # Use the OS-specific output dir

            if args.scan == "ts":
                deceiver.os_record()  # This will now save results in the specified OS-specific output directory
            elif args.scan == "od":
                deceiver.os_deceive()
            elif args.scan == "rr":
                deceiver.store_rsp()

        # Handle Port Deception
        elif args.scan == "pd":
            if not args.status:
                logging.error("Error: Port deception requires --status (open/close).")
                return

            deceiver = PortDeceiver(args.host)
            deceiver.deceive_ps_hs(args.status)

        logging.info("Deception process completed successfully.")

    except Exception as e:
        logging.error(f"Error during execution: {e}")

if __name__ == "__main__":
    main()
