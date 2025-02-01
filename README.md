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

To get the latest version, clone the repository:

git clone https://github.com/jimskchang/Camouflage-Cloak.git

After installing **Camouflage Cloak Server** in the Linux server, use the following command format:

	python3 main.py [--host <IP>] [--nic <nic_name>] [--scan <deceiver>] [--status <status>]

**Command Parameters**<br>

- --host <IP>          	 → Specifies the host IP to protect.
- --nic <nic_name>     	 → Specifies the network interface for packet transmission.
- --scan <deceiver>    	 Selects the deception method:<br>
			 ts → OS Template Synthesis<br>
			 od → OS Deceiver<br>
  			 pd → Port Deceiver<br>
- --status <status>    	 → Defines the status (open or close) of ports to deceive (only used with --scan ts).

**Example Usage**<br>

	python3 main.py --host 192.168.1.2 --nic eth0 --scan hs --status open

	python3 main.py --host 192.168.1.2 --scan od --os win7


## **Methods**
About --scan command, you can use ***pd***, ***od***, ***ts*** three key words after  --scan command to perform different camouflage methods.<br>
- **pd** : Port Deceiver
- **od** : OS Deceiver
- **ts** : Synthesize Deceptive OS Template


## **Test Environment Setup**
Prepare **three types of host (or VMs)**:
1.	**Attacker foothold** (with Nmap installed)
2.	**Protected servers** (with different OSs)
3.	**Camouflage Cloak server** (must have at least two NICs)

Ensure the **attacker foothold and protected server** communicate **through** the **Camouflage Cloak server**. Connect the protected server and attacker foothold to different NICs on the Camouflage Cloak server, then bridge the NICs.

***Create OS Synthesis Template***<br>
***STEP1: Navigate the setting.py and input the Host = 'Protected Host IP Address', and NIC='Protected Host NIC Card Name'

Navigate the Camouflage-Cloak folder and execute***<br>
	
 	python3 main.py --host <protected server's IP> --nic <protected server's NIC> --scan ts --os <OS template you want to synthesize e.g. win7/win10/centos>

***STEP2: Run Nmap OS detection on attacker foothold and observe the result***<br>

	nmap -O <protected server's IP>

***STEP3: Move to the OS template***<br>

Camouflage-Cloak creates the OS template in the current directory. To prevent overwriting and ensure proper deployment, move it to /os_record/<OS_template_name>.

***STEP4: Rerun Nmap OS detection to check the template is deployed properly***<br>

	nmap -O <protected server's IP>


***OS Deceiver Test***
***STEP1: Clone the repository on the Camouflage Cloak server***

git clone https://github.com/jimskchang/Camouflage-Cloak.git

***STEP2: Navigate to the Camouflage Cloak folder and execute***

	python3 main.py --host <protected server's IP> --scan od --os <OS template e.g. win7/win10/centos>

	(Optional: Specify a network interface using --nic)

***STEP3: Run Nmap OS detection from the attacker foothold and observe the result***

	nmap -O <protected server's IP>

***Port Deceiver Test***

***STEP1: Navigate to the Camouflage Cloak folder and execute***

	python3 main.py --host <<protected_server_IP> --scan pd --port <deceptive_port_number> --status <open|close>

***STEP2: Run Nmap port scanning from the attacker foothold and observe the result***

	nmap -sT <protected_server_IP>




