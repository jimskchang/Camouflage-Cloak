# **Camouflage Cloak: OS & Port Deception Against Nmap Scans**

**Camouflage Cloak** manipulates **TCP/IP stack parameters** to deceive **Nmap scans**, disguising the OS and misleading port scans.

## **How It Works**
1. **OS Deception:** Modifies TTL, TCP window sizes, RST behavior, and ICMP responses.
2. **Port Deception:** Alters SYN-ACK behavior, UDP responses, and service banners.
3. **Packet Manipulation:** Uses network traffic interception to fake OS fingerprints.

---

## **Features**
✅ **OS Fingerprinting Deception** – Mimic Windows, Linux, Mac, FreeBSD  
✅ **Port Scan Evasion** – Fake open/closed ports  
✅ **Traffic Capture** – Logs TCP, ICMP, UDP, and ARP responses  
✅ **Custom Configurations** – Supports various OS templates  

---

## **Installation**
### **Requirements**
- **Python 3.11+**
- **Linux OS** (Tested on Ubuntu, Kali)
- **Root Privileges** (For raw packet manipulation)

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
- **Customizable Configuration** - Easily configure IP and NIC settings

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
│   ├── __init__.py          # Makes the 'src' directory a Python package
│── README.md                # Documentation
│── main.py                  # Main execution script
```

---

## **Installation**
### **Requirements**
- **Python 3.11+**
- **Linux OS** (Tested on Ubuntu, Kali)
- **Root Privileges** (For raw packet manipulation)

### **Clone & Set Up**
```bash
git clone https://github.com/jimskchang/Camouflage-Cloak.git
cd Camouflage-Cloak
```

## **Usage**
### **Edit settings.py** to match your environment:
- HOST = "192.168.X.X"  # Camouflage-Cloak Host IP # Replace with the actual server IP
- NIC = "eth0"  # Camouflage-Cloak Host to Target Host Network Interface

## Environment Setup

### Required Hosts (or VMs)
1. **Attacker Foothold** – Runs **Nmap** for scanning.
2. **Target Host** – The protected server.
3. **Camouflage Cloak Server** – Intermediary system with **two NICs**.

### Configuration Steps
- Ensure traffic between the **attacker** and **target** passes through the **Camouflage Cloak Server**.
- Connect the **attacker** and **target** to the **two NICs** of the **Camouflage Cloak Server**.
- **Bridge the NICs** for seamless traffic flow.

## Running Camouflage Cloak ##
### Execute the Main Script
e.g.:
```bash
sudo python3 main.py [--host <192.168.1.200>] [--nic <nic_Name>] [--scan <ts>] [--dest </os_record>]
```

### **Available Modes**
| Mode         | Description |
|---------------|-------------|
| `--scan ts`   | Capture OS fingerprint for deception. |
| `--scan od`   | Perform OS deception (mimic a different OS). |
| `--scan pd`   | Deceive port scans by simulating open/closed ports. |
| `--os <OS>`   | Specify the OS template to mimic (e.g., `win10`, `linux5`). |
| `--status`    | Choose whether to simulate open or closed ports. |
| `--te <time>` | Set timeout duration for deception in minutes. |

## **Example Commands**

### **Step 1: Build OS Fingerprint**

**Build Template Synthesis**

***Step 1:*** Navigate to the Camouflage-Cloak
```bash
cd Camouflage-Cloak
```

***Step 2:*** execute the following instruction
```bash
sudo python3 main.py --host <protected server IP> --nic <network interface> --scan ts --dest /home/user/Camouflage-Cloak/os_record
```
The time out set in the --scan ts (to build Template Synthesis) is 300 second.  Therefore, you should perfom the Nmap scan immediately after you execute the --scan ts command. After two minutes it will return to the command mode for you to execute deception.

***Step 3:*** run Nmap OS detection on attacker host
```bash
sudo nmap -O <Target Host IP>
sudo nmap -A -p 1-65535 <Target Host IP>
sudo nmap --osscan-guess <Target Host IP>
```

***Step 4:*** Move back to Camouflage-Cloak host and execute cd
```bash
cd
```

***Step 5:*** change arp_record.txt, icmp_record.txt, txp_record.txt, and udp_record.txt to readable and writable
```bash
sudo chown -R $USER:$USER ~/Camouflage-Cloak/os_record
```

***Step 6:*** create the os folder (use win10 as example)
```bash
mkdir -p /home/user/Camouflage-Cloak/os_record/win10
```
***Step 7:*** move arp_record.txt, icmp_record.txt, txp_record.txt, and udp_record.txt to the os folder (use win10 as example)
```bash
cd Camouflage-Cloak
```

```bash
cd os_record
```

```bash
mv arp_record.txt win10/
```

```bash
mv icmp_record.txt win10/
```

```bash
mv tcp_record.txt win10/
```

```bash
mv udp_record.txt win10/
```

```bash
cd
```


**OS deceiver test**

***Step 1:*** Navigate to the Camouflage-Cloak
```bash
cd Camouflage-Cloak
```

***Step 2:*** execute the following instruction
```bash
sudo python3 main.py --host <Target Host IP> --nic <Target Host NIC> --scan od --os <OS template e.g. win7/win10/centos> --te <deceive time out time e.g. 6 = 6 minutes>
```

***Step 2:*** run Nmap OS detection on attacker foothold and observe the result
```bash
sudo nmap -O <Target Host IP>
```

**Deceive Port Scan (Simulating Open/Closed Ports)**
```bash
sudo python3 main.py --host <Target Host IP> --nic <Target Host NIC> --scan pd --status <e.g. open/close> --te <deceive time out time e.g. 6 = 6 minutes>
```

---

## Security & Legal Disclaimer

This tool is **for educational and security research purposes only**.

- **Do NOT use this tool on unauthorized networks.**
- **Ensure you have permission before deploying deception techniques.**
- The authors are **not responsible for misuse**.

---

## Contributors

- **Main**  - Shangkai Chang
- **Other Contributors** -  Zih-Siang Lin, Fany Yu
---

## Contact & Support

For issues, feature requests, or contributions:

- **Email**: 108356507@nccu.edu.tw

---


