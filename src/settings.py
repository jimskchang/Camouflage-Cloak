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
    """Fetch MAC address dynamically, supporting multiple methods."""
    
    possible_paths = [
        f"/sys/class/net/{nic}/address",  # Standard Linux path
        f"/proc/net/dev_mcast",           # Alternative path (rare)
    ]

    # Try to read from known paths
    for path in possible_paths:
        if os.path.exists(path):
            try:
                with open(path, "r") as f:
                    mac_address = f.read().strip()
                if mac_address:
                    logging.info(f"Successfully read MAC address for {nic}: {mac_address}")
                    return mac_address
            except Exception as e:
                logging.warning(f"Error reading {path}: {e}")

    # Fallback: Use `ip link` command
    try:
        output = subprocess.check_output(["ip", "link", "show", nic], text=True)
        for line in output.split("\n"):
            if "link/ether" in line:
                mac_address = line.split()[1].strip()
                logging.info(f"Successfully retrieved MAC from ip command: {mac_address}")
                return mac_address
    except subprocess.CalledProcessError as e:
        logging.error(f"Failed to retrieve MAC from `ip link show {nic}`: {e}")

    # Final fallback: Default placeholder
    logging.error(f"Failed to determine MAC address for {nic}. Returning placeholder MAC.")
    return "00:00:00:00:00:00"

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
