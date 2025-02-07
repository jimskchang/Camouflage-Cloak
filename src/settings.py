"""
=============================================
Camouflage Cloak Configuration - settings.py
=============================================

# NOTE: Global Constants
import os
import datetime
import subprocess

ETH_HEADER_LEN = 14
IP_HEADER_LEN = 20
ARP_HEADER_LEN = 28
TCP_HEADER_LEN = 20
UDP_HEADER_LEN = 8
ICMP_HEADER_LEN = 8
L3_PROC = ['ip', 'arp']
L4_PROC = ['tcp', 'udp', 'icmp']

# NOTE: Network Configuration
host = '192.168.23.200'
NIC = 'ens192'
NICAddr = '/sys/class/net/%s/address' % NIC
record_path = 'pkt_record.txt'
mac = "00:0C:29:1E:77:FD"  # Updated to string format
