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
├── setting.py               # Configuration file
├── utils.py                 # Utility functions (checksum, IP/MAC conversions)
├── Packet.py                # Packet processing logic
├── os_deceiver.py           # OS deception logic
├── port_deceiver.py         # Port deception logic
├── tcp.py                   # TCP connection handling
├── README.md                # Documentation
├── src/
│   ├── __init__.py          # Package initialization
│   ├── settings.py          # Config settings for hosts, NICs, etc.
│   ├── Packet.py            # Packet processing logic (modularized)
│   ├── tcp.py               # TCP helper functions
│   ├── os_deceiver.py       # OS deception logic (modularized)
│   ├── port_deceiver.py     # Port deception logic (modularized)
│   ├── utils.py             # Additional helper functions
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

### Install Dependencies

```bash
pip install -r requirements.txt
```

> Ensure Python3 is installed and correctly configured.

---

## Configuration

Edit **`settings.py`** to match your environment:

```python
# Required: Network Settings (Modify as needed)
CLOAK_NIC = "eth0"
TS_SERVER_NIC = "eth1"
TARGET_NIC = "eth2"

CLOAK_HOST = "192.168.1.1"
TS_SERVER = "192.168.1.200"
TARGET_HOST = "192.168.1.150"

CLOAK_MAC = "00:50:56:b0:10:e9"
TS_SERVER_MAC = "00:AA:BB:CC:DD:EE"
TARGET_MAC = "00:11:22:33:44:55"

TS_SERVER_OS = "win10"  # Modify based on the OS you want to deceive
```

> Ensure these values are set correctly before running the tool.

---

## Usage

### Run the Main Script

```bash
sudo python3 main.py --scan ts --host 192.168.1.200 --output-dir /os_record/win10
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

- **Your Name** (Maintainer) - [GitHub Profile](https://github.com/yourusername)
- **Other Contributors** - Add names here

---

## Contact & Support

For issues, feature requests, or contributions:

- **Open a GitHub Issue**: [Camouflage Cloak Issues](https://github.com/yourusername/CamouflageCloak/issues)
- **Email**: your.email@example.com

---

## License

This project is licensed under the **MIT License**. See **LICENSE** for details.

---

## References

- **TCP/IP Stack Fingerprinting**: [Read More](https://en.wikipedia.org/wiki/TCP/IP_stack_fingerprinting)
- **Network Deception Techniques**: [Security Journal](https://www.cybersecurity-insights.com)
- **Raw Sockets in Python**: [Python Docs](https://docs.python.org/3/library/socket.html)

