import os
import sys
import time
import json
import socket
import logging
import argparse
import subprocess
from multiprocessing import Process, JoinableQueue, cpu_count, Manager
from collections import defaultdict
from scapy.all import sniff, get_if_hwaddr, send, IP, TCP, Raw, Ether

# Setup paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SRC_DIR = os.path.join(BASE_DIR, "src")
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)

# Logging setup
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [%(processName)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

try:
    import settings
    from Packet import Packet
    from os_deceiver import OsDeceiver
    from port_deceiver import PortDeceiver
    from os_recorder import templateSynthesis, export_ja3_log
    import l7_tracker
except ImportError as e:
    logging.error(f"Critical Import Error: {e}")
    sys.exit(1)

# --- Stateful RDP Deception Logic ---

def handle_l7_deception(pkt, nic, connection_states):
    """
    Stateful deception handling HTTP and RDP (3389).
    """
    if not pkt.haslayer(TCP):
        return

    ip_layer = pkt[IP]
    tcp_layer = pkt[TCP]
    conn_id = (ip_layer.src, tcp_layer.sport, tcp_layer.dport)

    # 1. 初始化/獲取連線狀態
    if conn_id not in connection_states:
        connection_states[conn_id] = {'seq': 1000, 'ack': 0}
    state = connection_states[conn_id]

    # 2. 清理連線狀態 (RST/FIN)
    if tcp_layer.flags & 0x04 or tcp_layer.flags & 0x01:
        if conn_id in connection_states: del connection_states[conn_id]
        return

    # 3. 處理數據傳輸 (偽裝回應)
    if pkt.haslayer(Raw):
        raw_payload = pkt[Raw].load
        payload_len = len(raw_payload)
        state['ack'] = tcp_layer.seq + payload_len
        response_data = b""

        # --- 埠位模擬邏輯 ---
        if tcp_layer.dport == 80:
            # HTTP 模擬 (如前所述)
            response_data = b"HTTP/1.1 200 OK\r\nServer: Microsoft-IIS/10.0\r\nContent-Length: 0\r\n\r\n"
        
        elif tcp_layer.dport == 3389:
            # --- RDP 模擬 (二進位互動) ---
            # X.224 Connection Request (通常以 03 00 00 ... 開頭)
            if raw_payload.startswith(b"\x03\x00\x00"):
                logging.info(f"⚡ RDP Handshake initiated by {ip_layer.src}")
                # 回應 X.224 Connection Confirm
                response_data = b"\x03\x00\x00\x0b\x06\xd0\x00\x00\x12\x34\x00"

        # --- 發送回應 ---
        if response_data:
            fake_pkt = (
                IP(src=ip_layer.dst, dst=ip_layer.src) /
                TCP(
                    sport=tcp_layer.dport, 
                    dport=tcp_layer.sport, 
                    flags="PA", 
                    seq=state['seq'], 
                    ack=state['ack']
                ) /
                Raw(load=response_data)
            )
            send(fake_pkt, iface=nic, verbose=False)
            state['seq'] += len(response_data)

# --- Multiprocessing Workers ---

def packet_worker(queue, args, host_ip, connection_states, template_dict, pair_dict):
    """ Worker process to decompress and process packets in parallel. """
    while True:
        pkt_data = queue.get()
        if pkt_data is None: 
            queue.task_done()
            break
        
        try:
            pkt = Ether(pkt_data)
            
            # Stateful Deception (Active mode)
            if args.scan in ["od", "pd"]:
                handle_l7_deception(pkt, args.nic, connection_states)
            
            # Template Learning (Passive mode)
            if args.scan == "ts":
                packet = Packet(bytes(pkt))
                packet.interface = args.nic
                packet.unpack()
                proto = packet.l4 if packet.l4 else packet.l3
                templateSynthesis(packet, proto.upper(), template_dict, pair_dict, host_ip, base_path=args.dest, enable_l7=True)

        except Exception as e:
            logging.debug(f"Worker Error: {e}")
        finally:
            queue.task_done()

# --- Core Functions ---

def run_sniffing_engine(args, host_ip):
    packet_queue = JoinableQueue(maxsize=5000)
    
    manager = Manager()
    connection_states = manager.dict()
    template_dict = defaultdict(dict)
    pair_dict = {}

    # Start Worker Processes
    num_workers = max(1, cpu_count() - 1)
    workers = []
    for i in range(num_workers):
        p = Process(target=packet_worker, 
                    args=(packet_queue, args, host_ip, connection_states, template_dict, pair_dict), 
                    name=f"Worker-{i}")
        p.daemon = True
        p.start()
        workers.append(p)

    def producer(pkt):
        try:
            if pkt.haslayer(IP):
                packet_queue.put(bytes(pkt), block=False)
        except:
            pass # Queue full, drop packet

    logging.info(f"🚀 Engine Started on {args.nic}. Scan: {args.scan}. Workers: {num_workers}")
    
    # BPF Filter strictly restricted to IP for performance
    sniff(iface=args.nic, filter="ip", prn=producer, store=False, timeout=args.te * 60 if args.te else 300)

    # Shutdown Workers
    for _ in range(num_workers):
        packet_queue.put(None)
    packet_queue.join()

    # Save results
    if args.scan == "ts":
        save_templates(args.dest, template_dict)

def save_templates(dest_path, template_dict):
    os.makedirs(dest_path, exist_ok=True)
    for proto, records in template_dict.items():
        outdata = {k.hex(): v.hex() for k, v in records.items() if v}
        if outdata:
            with open(os.path.join(dest_path, f"{proto.lower()}_record.txt"), "w") as f:
                json.dump(outdata, f, indent=2)
    logging.info(f"📦 Templates saved to {dest_path}")

# --- Helper Utils ---

def set_nic_config(nic):
    try:
        subprocess.run(["ip", "link", "set", nic, "promisc", "on"], check=True)
        logging.info(f"🔁 NIC {nic} set to Promiscuous Mode")
    except Exception as e:
        logging.warning(f"Failed to set Promisc: {e}")

def get_host_ip(nic):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except: return "127.0.0.1"

# --- Main Entry ---

def main():
    parser = argparse.ArgumentParser(description="🛡️ High-Performance Stateful Deception Engine")
    parser.add_argument("--scan", choices=["ts", "od", "pd"], required=True)
    parser.add_argument("--host", help="Target Host IP")
    parser.add_argument("--nic", help="Network Interface")
    parser.add_argument("--dest", help="Destination for records")
    parser.add_argument("--os", help="OS to simulate")
    parser.add_argument("--status", help="Port config JSON string")
    parser.add_argument("--te", type=int, default=5, help="Timeout in minutes")
    args = parser.parse_args()

    args.nic = args.nic or settings.NIC_PROBE
    args.host = args.host or get_host_ip(args.nic)
    args.dest = args.dest or settings.OS_RECORD_PATH
    
    set_nic_config(args.nic)

    run_sniffing_engine(args, args.host)

if __name__ == "__main__":
    main()
