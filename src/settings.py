import os
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s]: %(message)s")

# 🛠️ **Global Constants**
ETH_HEADER_LEN = 14
IP_HEADER_LEN = 20
ARP_HEADER_LEN = 28
TCP_HEADER_LEN = 20
UDP_HEADER_LEN = 8
ICMP_HEADER_LEN = 8
L3_PROC = ["ip", "arp"]
L4_PROC = ["tcp", "udp", "icmp"]

# 🛠️ **Camouflage-Cloak Server Settings**
HOST = "192.168.23.206"  # Replace with the actual server IP
NIC = "ens192"  # Replace with the correct network interface

# ✅ **Validate NIC existence before using it**
NICAddr = f"/sys/class/net/{NIC}/address" if os.path.exists(f"/sys/class/net/{NIC}/address") else None

if NICAddr is None:
    logging.error(f"Network interface '{NIC}' does not exist. Check your settings!")
else:
    logging.info(f"Using network interface: {NIC}")

# ✅ **Get MAC Address Dynamically**
try:
    import netifaces

    if NICAddr:
        mac = netifaces.ifaddresses(NIC)[netifaces.AF_LINK][0]["addr"]
        logging.info(f"MAC Address for {NIC}: {mac}")
    else:
        raise ValueError("NIC is not valid")

except (ImportError, KeyError, ValueError) as e:
    logging.error(f"Failed to retrieve MAC address: {e}")
    mac = b"\x00\x50\x56\x8e\x35\x6f"  # Fallback MAC address

# ✅ **Packet Recording File**
record_path = "pkt_record.txt"

logging.info("Settings loaded successfully.")
