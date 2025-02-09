# Camouflage Cloak

## Network Deception & OS Camouflage System

**Camouflage Cloak** is a network deception system designed to mislead adversaries by mimicking different OS fingerprinting responses and manipulating network traffic. This tool helps security researchers and defenders detect, analyze, and counter reconnaissance techniques used by attackers.

---

## Features

- **Deceive OS Fingerprinting** - Mimic responses of various OS types
- **Port Deception** - Simulate open, closed, or filtered port states
- **Network Packet Recording** - Capture and store TCP, ICMP, ARP, and UDP responses
- **Customizable Configuration** - Easily configure IP, MAC, NIC, and OS settings
- **Supports Template Synthesis (TS) Server** - Create and store OS fingerprint templates

---

## Project Structure

```
CamouflageCloak/
├── main.py                  # Main execution script
├── README.md                # Documentation
├── src/
│   ├── settings.py          # Config settings for hosts, NICs, etc.
│   ├── Packet.py            # Packet processing logic (modularized)
│   ├── tcp.py               # TCP helper functions
│   ├── os_deceiver.py       # OS deception logic (modularized)
│   ├── port_deceiver.py     # Port deception logic (modularized)
│── README.md                # Documentation
│── main.py                  # Main execution script
```

---

## Installation

### Prerequisites

- **Python 3.6+**
- **Linux-based OS** (Tested on Ubuntu, Kali Linux)
- **Root/Sudo Privileges** (Required for raw socket manipulation)

### Clone the Repository

```bash
git clone https://github.com/yourusername/CamouflageCloak.git
cd CamouflageCloak
```

## Configuration

Edit **`settings.py`** to match your environment:

```python
# Camouflage-Cloak Server Network Configuration
HOST = '192.168.23.206'  # Replace based on your Camouflage-Cloak Server IP
NIC = 'ens192'  # Replace based on your Camouflage-Cloak Server NIC

# Camouflage-Cloak Server Input Manual MAC Address (set to None to auto-detect)
MANUAL_MAC_ADDRESS = '00:50:56:8e:35:6f'  # Replace based on your Camouflage-Cloak Server MAC address or set to None
```

> Ensure these values are set correctly before running the tool.

---

## Usage

### Run the Main Script
Eg:

```bash
sudo python3 main.py [--host <192.168.1.200>] [--nic <nic_Name>] [--scan <deceiver>] [--ststus <status>]
```

### Available Arguments

| Argument        | Description |
|----------------|-------------|
| `--scan ts`   | Run Template Synthesis (TS) scan to record OS fingerprints |
| `--scan od`   | Perform OS deception using pre-recorded fingerprints |
| `--scan rr`   | Record response packets |
| `--scan pd`   | Perform port deception |
| `--host IP`   | Specify the target IP |
| `--output-dir PATH` | Directory to store OS record files |

#### Example Commands

**Record OS Fingerprint for Windows 10**
```bash
sudo python3 main.py --scan ts --host 192.168.1.200 --output-dir /os_record/win10
```

**Deceive an OS Fingerprint Scan**
```bash
sudo python3 main.py --scan od --host 192.168.1.150 --os win10
```

**Deceive Port Scan (Simulating Open/Closed Ports)**
```bash
sudo python3 main.py --scan pd --host 192.168.1.150 --status open
```

---

## Logging & Output

- **Logs are stored in `/var/log/camouflage_cloak/cloak.log`**
- **OS scan records are saved in `/os_record/{OS_TYPE}/`**
- **Packet captures are stored in `pkt_record.txt`**

---

## Troubleshooting

### Permission Errors

If you get `Operation not permitted` errors, ensure:

- You are running the script **as root**:
  ```bash
  sudo python3 main.py ...
  ```
- Your network interface **supports packet injection** (check using `ifconfig` or `ip a`).

### Missing Dependencies

Run:
```bash
pip install -r requirements.txt
```

or manually install missing packages:
```bash
pip install scapy
```

### Check Logging for Errors

```bash
cat /var/log/camouflage_cloak/cloak.log
```

---

## Security & Legal Disclaimer

This tool is **for educational and security research purposes only**.

- **Do NOT use this tool on unauthorized networks.**
- **Ensure you have permission before deploying deception techniques.**
- The authors are **not responsible for misuse**.

---

## Contributors

- **Your Name** (Maintainer) - Shangkai Chang
- **Other Contributors** -  Zih-Siang Lin, Fany Yu
---

## Contact & Support

For issues, feature requests, or contributions:

- **Open a GitHub Issue**: [Camouflage Cloak Issues](https://github.com/jimskchang/CamouflageCloak/issues)
- **Email**: 108356507@nccu.edu.tw

---


## References

- **TCP/IP Stack Fingerprinting**: [Read More](https://en.wikipedia.org/wiki/TCP/IP_stack_fingerprinting)
- **Network Deception Techniques**: [Security Journal](https://www.cybersecurity-insights.com)
- **Raw Sockets in Python**: [Python Docs](https://docs.python.org/3/library/socket.html)

