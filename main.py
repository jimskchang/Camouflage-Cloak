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

# --- Stateful L7 Deception Logic ---

def handle_l7_deception(pkt, nic, connection_states):
    """
    Expands L7 deception with TCP SEQ/ACK tracking.
    """
    if not pkt.haslayer(TCP):
        return

    ip_layer = pkt[IP]
    tcp_layer = pkt[TCP]
    
    # 建立連線 ID (Source IP, Source Port, Dest Port)
    conn_id = (ip_layer.src, tcp_layer.sport, tcp_layer.dport)

    # 1. 初始化 TCP 狀態
    if conn_id not in connection_states:
        connection_states[conn_id] = {
            'seq': 1000,  # 初始序列號
            'ack': 0
        }
    
    state = connection_states[conn_id]

    # 2. 如果收到 RST 或 FIN，移除連線狀態
    if tcp_layer.flags & 0x04 or tcp_layer.flags & 0x01:
        if conn_id in connection_states:
            del connection_states[conn_id]
        return

    # 3. 處理數據傳輸 (如果有 Payload)
    if pkt.haslayer(Raw):
        payload_len = len(pkt[Raw].load)
        
        # 更新 ACK 為對方的 SEQ + Payload 長度
        state['ack'] = tcp_layer.seq + payload_len
        
        # 根據連接埠定義 Fake Banner
        banners = {
            21: b"220 (vsFTPd 3.0.3)\r\n",
            22: b"SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.1\r\n",
            80: b"HTTP/1.1 200 OK\r\nServer: Microsoft-IIS/10.0\r\nContent-Length: 0\r\n\r\n"
        }

        if tcp_layer.dport in banners:
            # 建立回應封包，使用同步後的 SEQ/ACK
            fake_pkt = (
                IP(src=ip_layer.dst, dst=ip_layer.src) /
                TCP(
                    sport=tcp_layer.dport, 
                    dport=tcp_layer.sport, 
                    flags="PA", # PSH + ACK
                    seq=state['seq'], 
                    ack=state['ack']
                ) /
                Raw(load=banners[tcp_layer.dport])
            )
            
            # 發送回應
            send(fake_pkt, iface=nic, verbose=False)
            
            # 更新本地的 SEQ (加上發送的 Payload 長度)
            state['seq'] += len(banners[tcp_layer.dport])

# --- Multiprocessing Workers ---

def packet_worker(queue, args, host_ip, connection_states, template_dict, pair_dict):
    """ Worker process to decompress and process packets. """
    while True:
        pkt_data = queue.get()
        if pkt_data is None: 
            queue.task_done()
            break
        
        try:
            # 重組封包
            pkt = Ether(pkt_data)
            
            # 1. 狀態化 L7 偽裝 (Active mode)
            if args.scan in ["od", "pd"]:
                handle_l7_deception(pkt, args.nic, connection_states)
            
            # 2. 樣本學習模式
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
    
    # 使用 Manager 共享連線狀態
    manager = Manager()
    connection_states = manager.dict()
    template_dict = defaultdict(dict)
    pair_dict = {}

    # Start Workers
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
            # 檢查是否為 IP 封包再放入佇列，減少不必要處理
            if pkt.haslayer(IP):
                packet_queue.put(bytes(pkt), block=False)
        except:
            pass # Queue full, drop packet

    logging.info(f"🚀 Engine Started on {args.nic}. Mode: {args.scan}")
    
    # BPF Filter 嚴格限制為 IP，以優化效能
    sniff(iface=args.nic, filter="ip", prn=producer, store=False, timeout=args.te * 60 if args.te else 300)

    # Shutdown
    for _ in range(num_workers):
        packet_queue.put(None)
    packet_queue.join()

    # Save results if in TS mode
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
    parser = argparse.ArgumentParser(description="🛡️ Stateful High-Performance Deception Engine")
    parser.add_argument("--scan", choices=["ts", "od", "pd"], required=True)
    parser.add_argument("--host", help="Target Host IP")
    parser.add_argument("--nic", help="Network Interface")
    parser.add_argument("--dest", help="Destination for records")
    parser.add_argument("--os", help="OS to simulate (e.g., Windows, Cisco)")
    parser.add_argument("--status", help="Port config JSON string")
    parser.add_argument("--te", type=int, default=5, help="Timeout in minutes")
    args = parser.parse_args()

    args.nic = args.nic or settings.NIC_PROBE
    args.host = args.host or get_host_ip(args.nic)
    args.dest = args.dest or settings.OS_RECORD_PATH
    
    set_nic_config(args.nic)

    run_sniffing_engine(args, args.host)
    
    if args.scan == "od":
        # OD 模式通常需要更細緻的 TCP Option 偽裝，建議整合到 handle_l7_deception
        logging.info("OS Deception active.")

if __name__ == "__main__":
    main()

