# 🛡 Camouflage Cloak

Camouflage Cloak is a Python-based deception toolkit designed to manipulate low-level network behavior and mislead active reconnaissance tools such as Nmap. It is intended to confuse OS fingerprinting and port scanning by simulating realistic network responses, helping conceal the true operating system and exposed services of a protected host.

This project focuses on:
- OS deception
- Port deception
- Packet-level fingerprint capture and reuse
- Dual-NIC traffic handling for transparent deception

---

## Overview

Camouflage Cloak works by intercepting and responding to network probes with crafted packets that resemble those expected from a specific operating system or service state. Instead of simply dropping or ignoring scan traffic, it actively generates deceptive replies to influence how scanners interpret the target.

This is especially useful for:
- defensive network research
- honeypot and deception testing
- red-team and blue-team simulation
- understanding how scanning tools interpret spoofed packet behavior

---

## How It Works

### OS Deception
The system can emulate OS-level behaviors such as:
- TTL values
- TCP window sizes
- TCP options, including timestamps
- ICMP and ARP responses

This allows the protected host to appear as another operating system to tools like Nmap.

### Port Deception
The toolkit can make ports appear:
- open
- closed
- filtered

It can simulate:
- SYN-ACK responses
- RST packets
- UDP responses
- fake service banners

### Fingerprint Capture
Camouflage Cloak can capture packet behavior during scans, convert those observations into reusable templates, and later replay them to reproduce the same deceptive fingerprint on demand.

---

## Features

- OS deception for Windows, Linux, Mac, FreeBSD, and Windows Server profiles
- Port scan simulation for open, closed, and filtered states
- Dynamic dual-NIC support using NIC_PROBE and NIC_TARGET
- Base64 packet serialization and packet parsing for ARP, IP, TCP, and ICMP
- Deceptive replies routed out through the probe interface
- CLI-driven workflow with hybrid configuration via settings.py
- TTL and TCP window presets tailored to target OS profiles

---

## Project Structure

```text
Camouflage-Cloak/
├── os_record/                  # Storage for target OS profile snapshots
│   └── structured_logs/        # Auto-generated analytical CSV exports
├── src/
│   ├── __init__.py             # Unified namespace package API contract
│   ├── settings.py             # Hardware bindings, static rules, and configuration
│   ├── Packet.py               # Packet validation and decoding engine
│   ├── tcp.py                  # TCP socket state and raw checksum utilities
│   ├── os_deceiver.py          # OS fingerprint spoofing engine
│   ├── port_deceiver.py        # Port deception and banner simulation
│   ├── ja3_extractor.py        # TLS ClientHello DPI analysis and JA3 matching
│   ├── l7_tracker.py           # Telemetry processing and dashboard plotting
│   └── log_manager.py          # Safe JSON-to-CSV logging and process management
├── main.py                     # CLI orchestration engine
├── README.md                   # Project documentation
└── LICENSE                     # License file (if present)
```

---

## Requirements

- Linux system (tested on Ubuntu/Kali)
- Python 3.11+
- sudo privileges for raw socket access

---

## System Setup

### Required Hosts

| Host | Role |
|------|------|
| Camouflage Cloak | Deception gateway between scanner and target |
| Target Host | The actual server being protected |
| Attacker | Nmap or another reconnaissance tool |

### Network Design

Ensure:
- NIC_PROBE connects to the scanner / attacker
- NIC_TARGET connects to the real target
- Camouflage Cloak is positioned between them and can intercept and manipulate traffic

---

## Configuration

Edit `src/settings.py` and set your network interfaces and host address:

```python
NIC_TARGET = 'ens192'     # Interface connected to the target host
NIC_PROBE  = 'ens224'     # Interface connected to the scanner/attacker
HOST = "192.168.23.206"   # Camouflage Cloak IP address
```

Make sure the interface names match your system.

---

## Usage

### 1. Build a Template from a Real Scan

```bash
sudo -E python3 main.py --host <target_ip> --nic <NIC_TARGET> --scan ts --dest ./os_record
```

Then run Nmap from the attacker machine during the capture window:

```bash
sudo nmap -O <target_ip>
```

After capture, move the generated files into a profile directory:

```bash
cd
sudo chown -R $USER:$USER ~/Camouflage-Cloak/os_record
mkdir -p os_record/win10
mv os_record/*.txt os_record/win10/
```

### 2. Run OS Deception

```bash
sudo -E python3 main.py --host <target_ip> --nic <NIC_TARGET> --scan od --os win10 --te 6
```

From the attacker machine, run Nmap again. It should identify the spoofed OS profile instead of the true system.

### 3. Run Port Deception

```bash
sudo -E python3 main.py --host <target_ip> --nic <NIC_TARGET> --scan pd --status open --te 6
```

This will cause Nmap to observe open ports even when they are not actually open.

---

## Notes

- This project requires elevated privileges because it uses raw sockets and packet-level manipulation.
- It is intended for research, defensive simulation, and authorized network testing.
- Behavior depends on the environment, interface configuration, and the exact scan tool being used.

---

## Author

Camouflage Cloak by Shangkai Chang

An open-source packet deception toolkit built for research, defense, and network-level deception experiments.

---

## Disclaimer

This project is designed for learning, defensive research, and authorized security testing. Do not use it against systems or networks without explicit permission.
