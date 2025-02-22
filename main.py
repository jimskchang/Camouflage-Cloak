import os
import argparse
import logging
import sys
import threading
import socket
import struct
import src.settings as settings
from src.port_deceiver import PortDeceiver
from src.os_deceiver import OsDeceiver

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

def collect_fingerprint(target_host, dest, max_packets=100):
    """
    Captures fingerprinting packets for the target host only.
    """
    logging.info(f"Starting OS Fingerprinting on {target_host} (Max: {max_packets} packets)")
    os.makedirs(dest, exist_ok=True)
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    target_ip = socket.inet_aton(target_host)
    start_time = time.time()
    packet_count = 0
    detected_os = "unknown"
    os_dest = os.path.join(dest, detected_os)
    os.makedirs(os_dest, exist_ok=True)
    logging.info(f"Storing data in: {os_dest}")

    try:
        while packet_count < max_packets:
            packet, addr = sock.recvfrom(65565)
            eth_protocol = struct.unpack("!H", packet[12:14])[0]
            proto_type = None
            ip_header = packet[14:34]
            ip_unpack = struct.unpack("!BBHHHBBH4s4s", ip_header)
            src_ip = ip_unpack[8]
            dest_ip = ip_unpack[9]
            
            if src_ip != target_ip and dest_ip != target_ip:
                continue  # Ignore packets not meant for the target host
            
            packet_files = {
                "arp": os.path.join(os_dest, "arp_record.txt"),
                "icmp": os.path.join(os_dest, "icmp_record.txt"),
                "tcp": os.path.join(os_dest, "tcp_record.txt"),
                "udp": os.path.join(os_dest, "udp_record.txt")
            }
            
            if eth_protocol == 0x0806:
                proto_type = "arp"
            elif eth_protocol == 0x0800:
                ip_proto = packet[23]
                if ip_proto == 1:
                    proto_type = "icmp"
                elif ip_proto == 6:
                    proto_type = "tcp"
                elif ip_proto == 17:
                    proto_type = "udp"
            
            if proto_type:
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
        logging.info("Fingerprinting completed. No OS deception performed.")
        return
    if args.od:
        if not args.dest or not args.os:
            logging.error("--dest and --os arguments are required for --od mode")
            sys.exit(1)
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
