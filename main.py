import logging
import argparse
import src.settings as settings
from src.port_deceiver import PortDeceiver
from src.os_deceiver import OsDeceiver

# Configure Logging
logging.basicConfig(
    format="%(asctime)s [%(levelname)s]: %(message)s",
    datefmt="%y-%m-%d %H:%M",
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
    parser.add_argument("--os", help="Specify OS to deceive")

    args = parser.parse_args()
    
    # Assign settings
    settings.host = args.host
    if args.nic:
        settings.NIC = args.nic

    # Validate Required Arguments
    if not args.scan:
        logging.error("Error: No scan technique is designated. Use --scan <technique>.")
        parser.print_help()
        return

    logging.info(f"Starting deception with technique: {args.scan}")

    # Handle OS Deception Techniques
    if args.scan in ["ts", "od", "rr"]:
        if not args.os:
            logging.error("Error: OS deception requires --os argument.")
            return

        deceiver = OsDeceiver(args.host, args.os)

        if args.scan == "ts":
            deceiver.os_record()
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

if __name__ == "__main__":
    main()
