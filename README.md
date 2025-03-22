# 🛡️ Camouflage Cloak: OS & Port Deception Against Nmap Scans

**Camouflage Cloak** is a Python-based deception system that manipulates low-level packet behavior to **defeat OS fingerprinting** and **mislead port scans** (especially from tools like **Nmap**). It uses **raw sockets**, **custom packet crafting**, and **fingerprint emulation**.

---

## 🚀 How It Works

### ✅ OS Deception
- Mimics real OS stack behaviors like:
  - TTL values
  - TCP window sizes
  - TCP options (e.g., timestamps)
  - ICMP & ARP replies

### ✅ Port Deception
- Makes **closed ports appear open**, or vice versa
- Simulates **SYN-ACK**, **RST**, **UDP responses**, and **fake service banners**

### ✅ Fingerprint Capture
- Captures packets during an Nmap scan and converts them into reusable templates

---

## 🔧 Features

- 🖥️ OS Deception (Windows, Linux, Mac, FreeBSD, Windows Server)
- 🎭 Port Scan Simulation (open, closed, filtered)
- 🧠 Dynamic dual NIC handling: NIC_PROBE vs NIC_TARGET
- 📦 Base64 packet serialization + ARP/IP/TCP/ICMP unpacking
- 📚 Auto-routing deceptive replies out NIC_PROBE
- 💡 CLI + settings.py hybrid configuration
- 🧰 TTL / TCP window presets based on target OS

---

## 📁 Project Structure
Camouflage-Cloak/
├── os_record/               # Stores OS fingerprint templates
├── src/
│   ├── settings.py          # Configurations: IPs, NICs, TTLs, MAC, etc.
│   ├── Packet.py            # Packet parsing (Ethernet, IP, TCP, UDP, ICMP, ARP)
│   ├── tcp.py               # TCP header logic & checksum tools
│   ├── os_deceiver.py       # OS deception engine
│   ├── port_deceiver.py     # Port deception engine
│   ├── init.py          # Exposes top-level module APIs
├── main.py                  # CLI runner: capture, deceive, spoof
├── README.md                # This file

---

## ⚙️ Requirements

- ✅ Linux (Tested on Ubuntu/Kali)
- ✅ Python **3.11+**
- ✅ `sudo` privileges (for raw sockets)

---

## System Setup

### Required Hosts

| Host | Role |
|------|------|
| 🧠 Camouflage Cloak | Deceives scans using dual NICs |
| 🎯 Target Host      | The server you're protecting |
| 🕵️ Attacker         | Nmap scanner sending probes  |

### Network Design

### Ensure:
- `NIC_PROBE` connects to scanner/attacker
- `NIC_TARGET` connects to the actual target
- Camouflage Cloak must bridge/intercept traffic between them

---

## ✍️ Configuration (Edit `src/settings.py`)

```python
NIC_TARGET = 'ens192'     # NIC to target host
NIC_PROBE  = 'ens224'     # NIC to Nmap/attacker
HOST = "192.168.23.206"   # Your Camouflage Cloak IP

OS_PRESETS = {
  "win10":  {"ttl": 128, "tcp_window": 8192},
  "win11":  {"ttl": 128, "tcp_window": 16384},
  "win2022": {"ttl": 128, "tcp_window": 32768},
  "linux":  {"ttl": 64, "tcp_window": 5840},
  "mac":    {"ttl": 64, "tcp_window": 65535}
}

## Usage

