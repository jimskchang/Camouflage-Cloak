import os
import sys
import time
import json
import socket
import logging
import argparse
import subprocess
from multiprocessing import Process, JoinableQueue, cpu_count, Manager
from scapy.all import sniff, sendp, IP, TCP, Raw, Ether

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
    from os_recorder import templateSynthesis
except ImportError as e:
    logging.error(f"Critical Dependency Failure: {e}")
    sys.exit(1)

# --- Process-Safe Stateful Deception Logic ---

def handle_l7_deception(pkt, nic, connection_states):
    """
    Stateful deception handling for HTTP and RDP (3389) endpoints.
    Tracks state modifications safely across separate process pools.
    """
    if not pkt.haslayer(TCP) or not pkt.haslayer(IP):
        return

    ip_layer = pkt[IP]
    tcp_layer = pkt[TCP]
    
    # Isolate MAC target identifiers dynamically to preserve link-layer cloaking
    src_mac = pkt[Ether].dst if pkt.haslayer(Ether) else "ff:ff:ff:ff:ff:ff"
    dst_mac = pkt[Ether].src if pkt.haslayer(Ether) else "00:00:00:00:00:00"
    
    conn_id = (ip_layer.src, tcp_layer.sport, tcp_layer.dport)

    # FIXED: Reassign local variables to safely update the Manager proxy map
    with getattr(connection_states, '_lock', None) or DummyLock():
        if conn_id not in connection_states:
            # FIXED: Synchronize sequence generation dynamically with client's incoming ack state
            connection_states[conn_id] = {'seq': tcp_layer.ack if tcp_layer.ack > 0 else 1000, 'ack': 0}
        state = dict(connection_states[conn_id])

    # Clean up connection states on teardown flags (RST=0x04, FIN=0x01)
    if tcp_layer.flags & 0x05:
        if conn_id in connection_states:
            del connection_states[conn_id]
        return

    if pkt.haslayer(Raw):
        raw_payload = pkt[Raw].load
        payload_len = len(raw_payload)
        state['ack'] = tcp_layer.seq + payload_len
        response_data = b""

        # --- Protocol Simulation ---
        if tcp_layer.dport == 80:
            # IIS Web Server Emulation Response Signature
            response_data = b"HTTP/1.1 200 OK\r\nServer: Microsoft-IIS/10.0\r\nContent-Length: 0\r\n\r\n"
        
        elif tcp_layer.dport == 3389:
            # X.224 RDP Connection Request Interception Handshake
            if raw_payload.startswith(b"\x03\x00\x00"):
                logging.info(f"⚡ RDP Handshake initiated securely by scanning client host: {ip_layer.src}")
                # Emit real, binary-accurate X.224 Connection Confirm parameters
                response_data = b"\x03\x00\x00\x0b\x06\xd0\x00\x00\x12\x34\x00"

        # --- Frame Assembly and Injection ---
        if response_data:
            # FIXED: Assemble a complete link-layer Ether frame to keep MAC addresses uniform
            fake_pkt = (
                Ether(src=src_mac, dst=dst_mac) /
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
            # FIXED: Inject directly into the interface wire using sendp()
            sendp(fake_pkt, iface=nic, verbose=False)
            
            state['seq'] += len(response_data)
            # Commit state records back to the shared Process proxy map object
            connection_states[conn_id] = state

class DummyLock(object):
    def __enter__(self): pass
    def __exit__(self, x, y, z): pass

# --- Multiprocessing Workers ---

def packet_worker(queue, args, host_ip, connection_states, template_dict, pair_dict):
    """
    Worker process running inside an isolated process pool.
    Decompresses and updates network fingerprints across shared data structures.
    """
    while True:
        pkt_data = queue.get()
        if pkt_data is None: 
            queue.task_done()
            break
        
        try:
            pkt = Ether(pkt_data)
            
            # Stateful Deception Handling Engine
            if args.scan in ["od", "pd"]:
                handle_l7_deception(pkt, args.nic, connection_states)
            
            # Template Passive Learning Subsystem
            if args.scan == "ts":
                packet = Packet(bytes(pkt))
                packet.interface = args.nic
                packet.unpack()
                proto = packet.l4 if packet.l4 else packet.l3
                
                if proto:
                    # Thread-safe signature isolation routine integration
                    templateSynthesis(packet, proto.upper(), template_dict, pair_dict, host_ip, base_path=args.dest, enable_l7=True)

        except Exception as e:
            logging.debug(f"Process Pool Thread Execution Error: {e}")
        finally:
            queue.task_done()

# --- Core Functions ---

def run_sniffing_engine(args, host_ip):
    packet_queue = JoinableQueue(maxsize=5000)
    
    # FIXED: Initialize all target matrices using a multiprocessing context Manager
    manager = Manager()
    connection_states = manager.dict()
    template_dict = manager.dict()
    pair_dict = manager.dict()

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
                # Queue bytes to prevent memory referencing leakage across threads
                packet_queue.put(bytes(pkt), block=False)
        except:
            pass # Queue full, drop frame gracefully under load spike

    logging.info(f"🚀 Multiprocessing Engine Started on {args.nic}. Mode: {args.scan.upper()}. Workers Online: {num_workers}")
    
    # BPF Filter restricted strictly to IP for line-speed matching performance
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
    try:
        # Convert proxy dictionary mappings safely back to flat storage files
        native_dict = dict(template_dict)
        for proto, records in native_dict.items():
            if isinstance(records, dict):
                outdata = {k.hex() if isinstance(k, bytes) else str(k): v.hex() if isinstance(v, bytes) else str(v) for k, v in records.items() if v}
                if outdata:
                    with open(os.path.join(dest_path, f"{str(proto).lower()}_record.txt"), "w") as f:
                        json.dump(outdata
