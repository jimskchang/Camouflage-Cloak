# Camouflage Cloak

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue)](https://www.python.org/downloads/)
[![Platform: Linux](https://img.shields.io/badge/platform-Linux-green)](https://www.linux.org/)
[![Research](https://img.shields.io/badge/category-Network%20Defense-orange)](https://github.com/jimskchang/Camouflage-Cloak)

Camouflage Cloak is a network deception toolkit that helps conceal a host’s true identity by manipulating packet-level behavior during active reconnaissance. It is designed to confuse OS fingerprinting and port-selection logic used by scanners such as Nmap, creating realistic misleading responses without altering the underlying service or host configuration.

This project is built for research, defensive testing, and controlled security experiments where deception-based detection evasion needs to be studied in a safe and authorized environment.

---

## Why It Matters

Network scanners infer device characteristics from small, observable signals:
- TTL values
- TCP window sizes
- TCP option ordering
- ICMP and ARP patterns
- Service response behavior

Camouflage Cloak uses these signals to produce deceptive, scanner-visible responses that make a protected host look like a different operating system or expose a different port posture than the real environment.

---

## What It Does

### OS deception
- Mimics OS stack fingerprints for common operating systems
- Alters response behavior to confuse OS detection
- Replays profile templates derived from observed scan behavior

### Port deception
- Simulates open, closed, or filtered ports
- Produces fake SYN-ACK and RST behavior
- Creates misleading service-level responses during reconnaissance

### Packet capture and replay
- Captures reconnaissance traffic during a scan
- Converts responses into reusable templates
- Replays those profiles on demand to recreate deceptive behavior

---

## Architecture

```text
Camouflage-Cloak/
├── os_record/                  # Captured template storage
│   └── structured_logs/        # Generated CSV analytics
├── src/
│   ├── __init__.py             # Public package API
│   ├── settings.py             # NIC mappings and runtime config
│   ├── Packet.py               # Packet validation and decoding
│   ├── tcp.py                  # TCP behavior utilities and checksum logic
│   ├── os_deceiver.py          # OS fingerprint spoofing engine
│   ├── port_deceiver.py        # Port deception logic
│   ├── learning_engine.py      # Adaptive behavior learning and profile refinement
│   ├── fingerprint_gen.py      # Synthetic fingerprint generation and template creation
│   ├── fingerprint_utils.py    # Shared helpers for fingerprint parsing and normalization
│   ├── os_recorder.py          # OS fingerprint recording and persistence
│   ├── response.py             # Response synthesis and packet emission helpers
│   ├── ja3_extractor.py        # TLS fingerprint extraction
│   ├── l7_tracker.py           # Telemetry and monitoring
│   ├── log_manager.py          # Logging and export layer
│   └── settings.py             # Runtime configuration and static mappings
├── main.py                     # CLI orchestration engine
├── README.md                   # Project documentation
├── LICENSE                     # License file
├── MULTIPROCESSING_ARCHITECTURE.md
├── MULTIPROCESSING_HARDENING.md
├── .gitignore                  # Git metadata exclusions
├── .idea/                      # IDE project metadata
├── os_record/sample.txt        # Sample generated capture artifact
└── src/response.py             # Packet response generation helpers
```

---

## Requirements

- Linux environment (tested on Ubuntu/Kali)
- Python 3.11+
- Root or sudo privileges for raw socket operations
- At least two NICs for split probe/target routing

---

## Quick Setup

### 1. Clone the repository

```bash
git clone https://github.com/jimskchang/Camouflage-Cloak.git
cd Camouflage-Cloak
```

### 2. Configure the environment

Edit `src/settings.py`:

```python
NIC_TARGET = 'ens192'     # Interface connected to the protected host
NIC_PROBE  = 'ens224'     # Interface connected to the scanner / attacker
HOST       = '192.168.23.206'
```

Verify interface names:

```bash
ip link show
```

---

## Usage

### Build a fingerprint profile

```bash
sudo -E python3 main.py --host <target_ip> --nic <NIC_TARGET> --scan ts --dest ./os_record
```

During the capture window, run Nmap from the attacker machine:

```bash
sudo nmap -O <target_ip>
```

After capture, organize the files:

```bash
cd
sudo chown -R $USER:$USER ~/Camouflage-Cloak/os_record
mkdir -p os_record/win10
mv os_record/*.txt os_record/win10/
```

### Enable OS deception

```bash
sudo -E python3 main.py --host <target_ip> --nic <NIC_TARGET> --scan od --os win10 --te 6
```

A second Nmap scan should report the spoofed OS profile rather than the true host characteristics.

### Enable port deception

```bash
sudo -E python3 main.py --host <target_ip> --nic <NIC_TARGET> --scan pd --status open --te 6
```

This behavior can be used to make ports appear open even when they are closed or filtered.

---

## Operational Notes

Camouflage Cloak is intended for authorized, controlled, and research-oriented deployments. In practice, it is most useful in environments where teams need to:
- analyze reconnaissance behavior
- test detection pipelines
- simulate deceptive endpoint posture
- support red-team and blue-team exercises

---

## Example Output

```text
[*] Camouflage Cloak initialized
[*] Probe NIC: ens224
[*] Target NIC: ens192
[*] Active OS profile: win10
[+] Listening for scan traffic...
[+] Returning deceptive SYN-ACK responses
[✓] Deception engine active
```

Nmap response example:

```text
Before: OS detection: Linux 5.x (99%)
After:  OS detection: Windows 10 (98%)
```

---

## Safety and Compliance

This project should only be used in environments where the operator has explicit authorization. It is designed for ethical research, defensive security engineering, and authorized lab testing.

---

## Contributing

Contributions are welcome. Pull requests should include tests or validation where possible and maintain clear documentation updates when behavior changes.

---

## Author

Shangkai Chang

Open-source packet deception toolkit for defensive research and controlled security experimentation.

---

## License

MIT License. See [LICENSE](LICENSE) for details.
