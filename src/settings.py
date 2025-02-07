"""
=============================================
Camouflage Cloak Configuration - settings.py
=============================================

# NOTE: Global Constants
import datetime

ETH_HEADER_LEN = 14
IP_HEADER_LEN = 20
ARP_HEADER_LEN = 28
TCP_HEADER_LEN = 20
UDP_HEADER_LEN = 8
ICMP_HEADER_LEN = 8
L3_PROC = ['ip', 'arp']
L4_PROC = ['tcp', 'udp', 'icmp']
host = '10.192.23.200'


# NOTE: Settings
NIC = 'ens192'
NICAddr = '/sys/class/net/%s/address' % NIC
record_path = 'pkt_record.txt'
mac = b'\x00\x0C\x29\x1E\x77\xFD'

