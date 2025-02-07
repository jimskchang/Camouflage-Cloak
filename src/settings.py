import os
import subprocess
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s]: %(message)s")

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
    """Fetch MAC address dynamically, supporting multiple methods for VM compatibility."""
    
    # Standard Linux method
    mac_path = f"/sys/class/net/{nic}/address"
    if os.path.exists(mac_path):
        try:
            with open(mac_path, "r") as f:
                mac_address = f.read().strip()
            if mac_address:
                logging.info(f"Successfully read MAC address for {nic}: {mac_address}")
                return mac_address
        except Exception as e:
            logging.warning(f"Error reading {mac_path}: {e}")

    # Fallback 1: Use `ip link show`
    try:
        output = subprocess.check_output(["ip", "link", "show", nic], text=True)
        for line in output.split("\n"):
            if "link/ether" in line:
                mac_address = line.split()[1].strip()
                logging.info(f"Successfully retrieved MAC from `ip link show`: {mac_address}")
                return mac_address
    except subprocess.CalledProcessError as e:
        logging.error(f"Failed to retrieve MAC from `ip link show {nic}`: {e}")

    # Fallback 2: Use `ifconfig` (for older Linux versions)
    try:
        output = subprocess.check_output(["ifconfig", nic], text=True)
        for line in output.split("\n"):
            if "ether" in line or "HWaddr" in line:  # Different formats
                mac_address = line.split()[1].strip()
                logging.info(f"Successfully retrieved MAC from ifconfig: {mac_address}")
                return mac_address
    except subprocess.CalledProcessError as e:
        logging.error(f"Failed to retrieve MAC from `ifconfig {nic}`: {e}")

    # Final fallback: Default MAC (VM Compatibility)
    logging.error(f"Failed to determine MAC address for {nic}. Returning placeholder MAC.")
    return "00:00:00:00:00:00"

# Get MAC address
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
