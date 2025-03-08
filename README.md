# Camouflage Cloak: OS & Port Deception Against Nmap Scans

**Camouflage Cloak** uses **OS deception** and **port deception** techniques to counteract malicious Nmap scans by providing false system information. By modifying **TCP/IP stack parameters**, it alters how the system responds to network probes, **disguising the OS** and **misleading port scans**.

## OS Deception Techniques
To evade OS detection, **Camouflage Cloak**:

1. **Modifies TCP window sizes** to mimic different OS behaviors.
2. **Alters ICMP responses** to disrupt fingerprinting.
3. **Blocks ICMP netmask requests** used in OS identification.
4. **Modifies TCP RST behavior**, confusing scans since Windows and Linux handle RST packets differently.
5. **Adjusts TTL (Time-To-Live) values** to imitate various OS defaults:
   - **Linux**: `64`
   - **Windows**: `128`
   - **FreeBSD/Mac**: `255`

## Port Deception Techniques
To mislead port scans, **Camouflage Cloak**:

1. **Modifies SYN-ACK behavior**, making closed ports appear open or vice versa.
2. **Sends fake service banners**, misleading attackers about running services.
3. **Alters UDP responses**, making all UDP ports appear open or closed.

## Combining OS & Port Deception
By integrating **OS deception** and **port deception**, **Camouflage Cloak** builds a **robust defense strategy** against reconnaissance tools like Nmap, effectively **misleading attackers** and **obscuring system details**.

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
├── os_record                # OS Template Synthesis
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

- **Python 3.11+**
- **Linux-based OS** (Tested on Ubuntu, Kali Linux)
- **Root/Sudo Privileges** (Required for raw socket manipulation)

### Clone the Repository

```bash
git clone https://github.com/jimskchang/CamouflageCloak.git
cd CamouflageCloak
```

## Configuration

Edit **`settings.py`** to match your environment:

```python
# Camouflage-Cloak Server Network Configuration
# 🛠️ **Camouflage-Cloak Server Settings**
HOST = "192.168.23.206"  # Replace with the actual server IP
NIC = "ens192"  # Replace with the correct network interface
```

> Ensure these values are set correctly before running the tool.

---

## Usage
Prepare 3 hosts (or VMs), which include an attacker foothold (with Nmap), a protected server (Target Host), and a Camouflage Cloak server (at least contains 2 NICs). Make the traffic between the attacker foothold and the protected server can pass through the Camouflage Cloak server (make sure they all connect to the Camouflage Cloak server's 2 NIC respectively and then bridging the NICs)

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

**Build Template Synthesis**

***Step 1:***clone this repository to the Camouflage Cloak server
```bash
git clone https:"//github.com/jimskchang/Camouflage-Cloak.git
```

***Step 2:***cd to the Camouflage-Cloak folder and execute the following instruction
```bash
sudo python3 main.py --host <protected server IP> --scan ts --os <host OS template you want to synthesize e.g. "win10" or "centos"> 
```

***Step 3:***run Nmap OS detection on attacker 
```bash
sudo nmap -O <Protected Server IP>
```
The time out set in the --scan ts (to build Template Synthesis) is 120 second.  Therefore, you should perfom the Nmap scan immediately after you execute the --scan ts command. After two minutes it will return to the command mode for you to execute deception.

***Step 4:*** Check the Template
```bash
Camouflage Cloak will intercept Nmap fingerprinting packets and generate the packetts template to /os_record/<"OS template name"> to deploy the template correctly.
```

**OS deceiver test**

***Step 1:***clone this repository to the Camouflage Cloak server
```bash
git clone https:"//github.com/jimskchang/Camouflage-Cloak.git
```

***Step 2:***cd to the Camouflage-Cloak folder and execute the following instruction
```bash
sudo python3 main.py --host <protected server IP> --nic <protected server NIC> --scan od --os <OS template e.g. win7/win10/centos> 
```

***Step 3:***run Nmap OS detection on attacker foothold and observe the result
```bash
sudo nmap -O <Protected Server IP>
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

- **Email**: 108356507@nccu.edu.tw

---


