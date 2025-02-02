"""
=============================================
Camouflage Cloak Configuration - settings.py
=============================================

This script contains configurations for the Camouflage Cloak system, including:
- Network settings (Manual Input Required)
- NIC & MAC configurations for all hosts (Manual Input Required)
- Logging & Output Directory Management
- Support for running `--scan ts` via Python

## Installation & Setup Instructions:

###  Manually Edit `settings.py`
   Set the correct **IP addresses, NICs, and MACs** based on your environment.

   ```python
   # REQUIRED: Cloak Host NIC (To be modified)
   CLOAK_NIC = "ens192"

   # REQUIRED: TS Server NIC (To be modified)
   TS_SERVER_NIC = "ens192"

   # REQUIRED: Target Host NIC (To be modified)
   TARGET_NIC = "ens192"

   # REQUIRED: Target Host IP (To be modified)
   TARGET_HOST = "192.168.23.202"

   # REQUIRED: Cloak Host IP (To be modified)
   CLOAK_HOST = "192.168.23.206"

   # REQUIRED: TS Server IP (To be modified)
   TS_SERVER = "192.168.23.201"

   # REQUIRED: TS Server OS (To be modified: win10, win7, linux, etc.)
   TS_SERVER_OS = "win10"

   # REQUIRED: Cloak Host MAC (To be modified)
   CLOAK_MAC = "00:50:56:b0:10:e9"

   # REQUIRED: TS Server MAC (To be modified)
   TS_SERVER_MAC = "00:AA:BB:CC:DD:EE"

   # REQUIRED: Target Host MAC (To be modified)
   TARGET_MAC = "00:11:22:33:44:55"
