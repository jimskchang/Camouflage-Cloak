# 🛡 Camouflage Cloak

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue)](https://www.python.org/downloads/)
[![Platform: Linux](https://img.shields.io/badge/platform-Linux-green)](https://www.linux.org/)
[![Research](https://img.shields.io/badge/category-Network%20Deception-purple)](https://github.com/jimskchang/Camouflage-Cloak)

A Python-based network deception system that manipulates packet-level behavior to confound OS fingerprinting and port scanning reconnaissance tools. Camouflage Cloak actively generates spoofed network responses, leveraging dual-NIC architectures to transparently intercept and deceive common vulnerability scanning workflows.

Key application: defensive network research, honeypot simulation, and red-team/blue-team exercises.

---

## Abstract

Active reconnaissance tools such as Nmap infer target system properties through probing behaviors that elicit predictable protocol responses. By synthesizing authentic OS-level artifacts—TTL distributions, TCP window sizes, ICMP and ARP signatures—Camouflage Cloak can convincingly misrepresent system identity and service exposure. This toolkit captures live scanning telemetry, derives reusable fingerprint templates, and replays deceptive responses in real time, enabling controlled network deception for research and defensive purposes.

---

## Core Capabilities

| Feature | Description |
|---------|-------------|
| OS Spoofing | Emulate Windows, Linux, macOS, FreeBSD, and Windows Server profiles via authentic stack behavior |
| Port Simulation | Present arbitrary port states (open, closed, filtered) with service banner fabrication |
| Fingerprint Synthesis | Capture live scanning probes, extract behavioral templates, and regenerate them on demand |
| Dual-NIC Routing | Transparent interception via independent probe and target interfaces |
| Packet Introspection | Base64 serialization, ARP/IP/TCP/ICMP unpacking, and raw checksum validation |

---

## How It Works

### Operational Model

```text
[Attacker / Scanner]
        ↓
  [NIC_PROBE] ← Camouflage Cloak → [NIC_TARGET]
                      ↓
              [Target Host]
```

Camouflage Cloak intercepts probe traffic on `NIC_PROBE`, processes it through OS and port deception engines, and returns spoofed responses to the scanner while remaining transparent to the target host.

### OS Deception

Authentic OS fingerprinting relies on distinctive stack behavior:
- TTL values
- TCP window sizes and option sets
- ICMP and ARP response patterns

The toolkit records these signatures during template synthesis and replays them to produce scanner-observable OS misidentification.

### Port Deception

Port scanning typically depends on TCP and UDP response analysis:
- Closed ports → RST or ICMP unreachable
- Filtered ports → no response / timeout
- Open ports → SYN-ACK acceptance

Camouflage Cloak synthesizes crafted responses like SYN-ACK, RST, and fake banners to simulate arbitrary port states.

---

## System Architecture

```text
Camouflage-Cloak/
├── os_record/                  # OS profile snapshot storage
│   └── structured_logs/        # Analytical CSV exports
├── src/
│   ├── __init__.py             # Public API contract
│   ├── settings.py             # Network configuration and static rules
│   ├── Packet.py               # Frame validation and decoding
│   ├── tcp.py                  # TCP state machine and checksum utilities
│   ├── os_deceiver.py          # OS fingerprint spoofing engine
│   ├── port_deceiver.py        # Port state and banner simulation
│   ├── ja3_extractor.py        # TLS ClientHello DPI and JA3 matching
│   ├── l7_tracker.py           # Telemetry collection and visualization
│   └── log_manager.py          # Process-safe JSON-to-CSV logging
├── main.py                     # CLI orchestration and parallelized dispatch
├── README.md                   # Documentation
└── LICENSE                     # License file
```

---

## Requirements

- Linux (Ubuntu or Kali recommended)
- Python 3.11+
- `sudo` access for raw socket access
- Dual Ethernet interfaces for `NIC_PROBE` and `NIC_TARGET`

---

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/jimskchang/Camouflage-Cloak.git
cd Camouflage-Cloak
```

### 2. Configure the interfaces

Edit `src/settings.py`:

```python
NIC_TARGET = 'ens192'          # Interface connected to the target host
NIC_PROBE  = 'ens224'          # Interface connected to the scanner / attacker
HOST       = "192.168.23.206"  # Camouflage Cloak IP address
```

Verify interface names:

```bash
ip link show
```

### 3. Check Python

```bash
python3 --version
```

---

## Quick Start

### 1. Template synthesis

Capture a real host signature during a live scan:

```bash
sudo -E python3 main.py --host <target_ip> --nic <NIC_TARGET> --scan ts --dest ./os_record
```

From the attacker machine:

```bash
sudo nmap -O <target_ip>
```

Then organize the generated output:

```bash
cd
sudo chown -R $USER:$USER ~/Camouflage-Cloak/os_record
mkdir -p os_record/win10
mv os_record/*.txt os_record/win10/
```

### 2. Run OS deception

```bash
sudo -E python3 main.py --host <target_ip> --nic <NIC_TARGET> --scan od --os win10 --te 6
```

Run Nmap again from the attacker side. It should report the spoofed OS profile rather than the true system.

### 3. Run port deception

```bash
sudo -E python3 main.py --host <target_ip> --nic <NIC_TARGET> --scan pd --status open --te 6
```

Nmap will observe open ports even when they are not actually open.

---

## Command Reference

| Mode | Command | Purpose |
|------|---------|---------|
| Template Synthesis | `--scan ts` | Capture real Nmap behavior for profile generation |
| OS Deception | `--scan od --os <profile>` | Spoof target operating system |
| Port Deception | `--scan pd --status <state>` | Simulate arbitrary port states |

Common arguments:
- `--host <IP>` — target IP address
- `--nic <interface>` — target network interface
- `--te <seconds>` — runtime duration
- `--dest <path>` — output directory for templates

---

## Use Cases

- Defensive research and protocol analysis
- Honeypot simulation to misdirect reconnaissance
- Red-team and blue-team exercises
- Network forensics and traffic analysis training

---

## Screenshots / Example Output

```text
[*] Camouflage Cloak Engine Initialized
[*] NIC_PROBE: ens224 | NIC_TARGET: ens192
[*] OS Profile: win10 (TTL=128, Window=65535)
[+] Listening for probes on ens224...
[+] SYN → SYN-ACK (spoofed Windows response)
[✓] Deception active. Engine uptime: 6s
```

Example Nmap result:

```text
Before: OS detection: Linux 5.x (99%)
After:  OS detection: Windows 10 (98%)
```

---

## Ethical Considerations

- Use only on Systems and networks with explicit authorization.
- Intended for academic, defensive, and controlled security test environments.
- Unauthorized deception may violate applicable laws and organizational policy.

---

## Known Limitations

- Advanced stateful firewalls may detect inconsistencies in prolonged sessions.
- Multilayer verification (network + TLS + app-level fingerprinting) may challenge spoofing.
- Timing jitter and latency can reveal synthetic behavior.

---

## Contributing

Contributions are welcome. Please keep changes focused and include documentation updates when relevant.

---

## References

- NIST SP 800-42: Guidelines on Network Security Testing
- Nmap OS Detection methodology
- RFC 1191: Path MTU Discovery

---

## Author

Shangkai Chang

Camouflage Cloak is an open-source network deception toolkit created for research, defense, and controlled security experimentation.

---

## License

MIT License. See [LICENSE](LICENSE) for details.

---

## Disclaimer

This software is provided for educational, defensive, and authorized security research use only. The author assumes no responsibility for misuse or unauthorized deployment.
