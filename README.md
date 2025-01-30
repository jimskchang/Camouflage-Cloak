# Camouflage Cloak
## **Why Camouflage Cloak?**

The growing sophistication of cyberattacks challenges organizations relying on digital infrastructure, often outpacing traditional defenses. Attackers leverage reconnaissance tools to exploit vulnerabilities and craft targeted payloads. 

**Camouflage Cloak** is a deception-based defense that counters active reconnaissance by creating a **“zero-vulnerability surface.”** It misleads attackers with deceptive intelligence and forged operating system responses, effectively hiding real system details.

## **Why Did We Create Camouflage Cloak?**  

From an attacker's reconnaissance perspective, the **attack surface** consists of three key components:  

1. **Method** – Malicious reconnaissance  
2. **Channel** – TCP/IP  
3. **Data** – Network packets  

Minimizing the attack surface is crucial for reducing exploitable entry points and vulnerabilities. **Camouflage Cloak** implements a **defensive deception solution** on the target network, transparently sniffing both malicious and normal traffic while forging host responses.

By mimicking a target system, Camouflage Cloak **obscures the true identity** of systems behind it, making reconnaissance efforts ineffective.
 

## **Running Camouflage Cloak**
**Installation**
To get the latest version, clone the repository:

git clone https://github.com/jimskchang/Camouflage-Cloak.git

**Usage**
After installing **Camouflage Cloak Server** in the Linux server, use the following command format:

	python3 main.py [--host <IP>] [--nic <nic_name>] [--scan <deceiver>] [--status <status>]

**Command Parameters**<br>

- --host <IP>          	 → Specifies the host IP to protect.
- --nic <nic_name>     	 → Specifies the network interface for packet transmission.
- --scan <deceiver>    	 Selects the deception method:<br>
			 ts → OS Template Synthesis<br>
			 od → OS Deceiver<br>
  			 hs → Port Deceiver<br>
- --status <status>    	 → Defines the status (open or close) of ports to deceive (only used with --scan hs).

**Example Usage**<br>

	python3 main.py --host 192.168.1.2 --nic eth0 --scan hs --status open

	python3 main.py --host 192.168.1.2 --scan od --os win7


## **Camouflage Cloak Methods**
The --scan parameter supports the following deception methods:<br>

	-	pd → Port Deceiver
	-	od → OS Deceiver
	-	ts → Synthesize Deceptive OS Template


## **Simple Test Setup**
**Prerequisites**
Prepare **three hosts (or VMs)**:
1.	**Attacker foothold** (with Nmap installed)
2.	**Protected server**
3.	**Camouflage Cloak server** (must have at least two NICs)

Ensure the **attacker foothold and protected serve**r communicate **through** the **Camouflage Cloak server**. Connect the protected server and attacker foothold to different NICs on the Camouflage Cloak server, then bridge the NICs.

## **OS Deceiver Test**
***STEP1: Clone the repository on the Camouflage Cloak server***

git clone https://github.com/jimskchang/Camouflage-Cloak.git

***STEP2: Navigate to the Camouflage Cloak folder and execute***

	python3 main.py --host <protected server's IP> --scan od --os <OS template e.g. win7/win10/centos>

	(Optional: Specify a network interface using --nic)

***STEP3: Run Nmap OS detection from the attacker foothold and observe the result***

	nmap -O <protected server's IP>

## **Template Synthesis Test**
***STEP1: Navigate the Camouflage-Cloak folder and execute***

	python3 main.py --host <protected server's IP> --scan ts --os <OS template you want to synthesize e.g. win7/win10/centos>

***STEP2: Run Nmap OS detection on attacker foothold and observe the result***

	nmap -O <protected server's IP>

***STEP3: Move the Template***

Camouflage-Cloak generates the template in your current directory to prevent overriding. Move them to:
/os_record/<OS_template_name>

This ensures the template is deployed correctly.

***STEP4: Rerun Nmap OS detection to check the template is deployed properly***

	nmap -O <protected server's IP>


## ***Port Deceiver Test***

***STEP1: Navigate to the Camouflage Cloak folder and execute***

	python3 main.py --host <<protected_server_IP> --scan pd --port <deceptive_port_number> --status <open|close>

***STEP2: Run Nmap port scanning from the attacker foothold and observe the result***

	nmap -sT <protected_server_IP>




