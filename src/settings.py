import os
import subprocess
import logging

# Global Constants
ETH_HEADER_LEN = 14
IP_HEADER_LEN = 20
ARP_HEADER_LEN = 28
TCP_HEADER_LEN = 20
UDP_HEADER_LEN = 8
ICMP_HEADER_LEN = 8
L3_PROC = ['ip', 'arp']
L4_PROC = ['tcp', 'udp', 'icmp']

# Network Configuration
host = '192.168.23.200'
NIC = 'ens192'  # Change this if your NIC is different

def get_mac_address(nic):
    """Fetches MAC address dynamically and handles errors properly."""
    mac_path = f"/sys/class/net/{nic}/address"

    if not os.path.exists(mac_path):
        logging.error(f"NIC path does not exist: {mac_path}")
        return "00:00:00:00:00:00"

    try:
        with open(mac_path, "r") as f:
            mac_address = f.read().strip()
        if mac_address:
            logging.info(f"Successfully read MAC address for {nic}: {mac_address}")
            return mac_address
        else:
            logging.warning(f"MAC address is empty for {nic}")
            return "00:00:00:00:00:00"
    except Exception as e:
        logging.warning(f"Unable to read NIC address from {nic}: {e}")
        return "00:00:00:00:00:00"  # Default placeholder MAC

NICAddr = get_mac_address(NIC)

# Default OS record output path
TARGET_OS_OUTPUT_DIR = os.path.join(os.getcwd(), "os_records")
os.makedirs(TARGET_OS_OUTPUT_DIR, exist_ok=True)

def get_os_record_dir(custom_path=None):
    """Ensures the OS record directory exists."""
    os_record_dir = custom_path if custom_path else TARGET_OS_OUTPUT_DIR
    os.makedirs(os_record_dir, exist_ok=True)
    return os_record_dir

# Record Path
record_path = 'pkt_record.txt'
mac = NICAddr  # Assign the resolved MAC address
