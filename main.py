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
        port_scan_tech = args.scan.lower()  # Convert to lowercase to avoid case sensitivity issues

        if port_scan_tech == "ts":  # Capture fingerprint ONLY, no deception!
            logging.info("Executing fingerprint capture (TS mode)...")
            deceiver = OsDeceiver(args.host, args.os)
            deceiver.os_record()  # ✅ Correct function to execute
            return  # ⬅️ Prevents any other execution

        elif port_scan_tech == "od":  # OS Deception
            logging.info("Executing OS Deception...")
            if args.os is None:
                logging.warning("No OS specified for deception.")
            else:
                deceiver = OsDeceiver(args.host, args.os)
                deceiver.os_deceive()

        elif port_scan_tech == "rr":  # Response Recording
            logging.info("Recording response packets...")
            deceiver = OsDeceiver(args.host, args.os)
            deceiver.store_rsp()

        elif port_scan_tech == "pd":  # Port Deception
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
