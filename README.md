# 🛡 Camouflage Cloak: OS & Port Deception Against Nmap Scans

**Camouflage Cloak** is a Python-based deception system that manipulates low-level packet behavior to **defeat OS fingerprinting** and **mislead port scans** (especially from tools like **Nmap**). It uses **raw sockets**, **custom packet crafting**, and **fingerprint emulation**.

---

##  How It Works

###  OS Deception
- Mimics real OS stack behaviors like:
  - TTL values
  - TCP window sizes
  - TCP options (e.g., timestamps)
  - ICMP & ARP replies

###  Port Deception
- Makes **closed ports appear open**, or vice versa
- Simulates **SYN-ACK**, **RST**, **UDP responses**, and **fake service banners**

###  Fingerprint Capture
- Captures packets during an Nmap scan and converts them into reusable templates

---

## 🔧 Features

-  OS Deception (Windows, Linux, Mac, FreeBSD, Windows Server)
-  Port Scan Simulation (open, closed, filtered)
-  Dynamic dual NIC handling: NIC_PROBE vs NIC_TARGET
-  Base64 packet serialization + ARP/IP/TCP/ICMP unpacking
-  Auto-routing deceptive replies out NIC_PROBE
-  CLI + settings.py hybrid configuration
-  TTL / TCP window presets based on target OS

---

##  Project Structure
Camouflage-Cloak/
├── os_record/                  # Target database store for profile snapshots
│   └── structured_logs/        # Auto-generated analytical time-series CSV dumps
├── src/
│   ├── __init__.py             # Unified namespace package manager public API contract
│   ├── settings.py             # Settings matrix: hardware MAC bindings, static maps, rules
│   ├── Packet.py               # Boundary-safe link-frame validation and decoding engine
│   ├── tcp.py                  # Transport layer socket state creation & raw Internet checksums
│   ├── os_deceiver.py          # OS network profile signature spoofing implementation
│   ├── port_deceiver.py        # Port connection handler & banner simulation subsystem
│   ├── ja3_extractor.py        # Dynamic TLS ClientHello DPI engine & standard JA3 matching
│   ├── l7_tracker.py           # Thread-safe telemetry processing & real-time plotting dashboard
│   └── log_manager.py          # Process-safe JSON-to-CSV database logging engine
├── main.py                     # High-performance parallelized CLI orchestration engine
└── README.md                   # Core system documentation manual

---

## ⚙️ Requirements

-  Linux (Tested on Ubuntu/Kali)
-  Python **3.11+**
-  `sudo` privileges (for raw sockets)

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

NIC_TARGET = 'ens192'     # NIC to target host
NIC_PROBE  = 'ens224'     # NIC to Nmap/attacker
HOST = "192.168.23.206"   # Your Camouflage Cloak IP

## Usage
### Build Template Synthesis
```python
sudo -E python3 main.py --host <target_ip> --nic <NIC_TARGET> --scan ts --dest ./os_record
```

**Then run Nmap from the attacker machine during the 3-min capture window:**
```python
sudo nmap -O <target_ip>
```
**Move captured files:**
```python
cd
sudo chown -R $USER:$USER ~/Camouflage-Cloak/os_record
mkdir -p os_record/win10
mv os_record/*.txt os_record/win10/
```

## Run OS Deception
```python
sudo -E python3 main.py --host <target_ip> --nic <NIC_TARGET> --scan od --os win10 --te 6
```

Then run Nmap again from attacker. It should detect the spoofed OS.

##  Run Port Deception
```python
sudo -E python3 main.py --host <target_ip> --nic <NIC_TARGET> --scan pd --status open --te 6
```
Nmap will see open ports even if they aren’t.

## Author
Camouflage Cloak by Shangkai Chang
Open-source packet deception toolkit built for research and defense.
