import os
import argparse
import logging
import sys
import threading
import src.settings as settings
from src.port_deceiver import PortDeceiver

def disable_deception():
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

def detect_os_from_packets(packet):
    """
    Since OS detection is not automated, always store packets in 'unknown'.
    Users must manually move data to the correct OS folder after scanning.
    """
    return "unknown"

def collect_fingerprint(target_host, dest, max_packets=100):
    import socket
    import struct
    import time
    logging.info(f"Starting OS Fingerprinting on {target_host} (Max: {max_packets} packets)")
    os.makedirs(dest, exist_ok=True)
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    start_time = time.time()
    packet_count = 0
    detected_os = None
    os_dest = None

    try:
        while packet_count < max_packets:
            # Removed time limit to allow continuous packet collection
                logging.info("Timeout reached. Exiting OS fingerprinting mode.")
                break
            packet, addr = sock.recvfrom(65565)
            eth_protocol = struct.unpack("!H", packet[12:14])[0]
            proto_type = None
            
            if detected_os is None or detected_os == "unknown":
                detected_os = detect_os_from_packets(packet)
                os_dest = os.path.join(dest, detected_os)
                if detected_os != "unknown":
                os.makedirs(os_dest, exist_ok=True)
                logging.info(f"Detected OS: {detected_os}, storing data in: {os_dest}")
            
            packet_files = {
                "arp": os.path.join(os_dest, "arp_record.txt"),
                "icmp": os.path.join(os_dest, "icmp_record.txt"),
                "tcp": os.path.join(os_dest, "tcp_record.txt"),
                "udp": os.path.join(os_dest, "udp_record.txt")
            }
            
            if proto_type and os_dest:
                with open(packet_files[proto_type], "a") as f:
                    f.write(str(packet) + "\n")
                packet_count += 1
                logging.info(f"Captured {proto_type.upper()} Packet ({packet_count})")
        
        if packet_count == 0:
            logging.warning("No packets captured! Check network interface settings and traffic.")
        logging.info(f"OS Fingerprinting Completed. Captured {packet_count} packets.")
    except KeyboardInterrupt:
        logging.info("User interrupted capture. Exiting...")
    except Exception as e:
        logging.error(f"Error while capturing packets: {e}")
    logging.info("Returning to command mode.")

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
    if args.scan == "ts":
        if not args.dest:
            logging.error("--dest argument is required for ts mode")
            sys.exit(1)
        logging.info(f"Executing OS Fingerprinting on {args.host}...")
        collect_fingerprint(target_host=args.host, dest=args.dest, max_packets=100)
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
