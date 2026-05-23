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

# Setup absolute path mappings
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
    from os_recorder import templateSynthesis
    import l7_tracker
    import response
except ImportError as e:
    logging.error(f"Fatal Initialization Error: Missing core architectural components: {e}")
    sys.exit(1)

def handle_l7_deception(pkt, nic, connection_states, shared_fingerprint_proxy):
    """
    Process-safe active connection generator designed to handle 
    multi-process tracking state mutations perfectly without dropping sequence windows.
    """
    if not pkt.haslayer(TCP) or not pkt.haslayer(IP):
        return

    ip_layer = pkt[IP]
    tcp_layer = pkt[TCP]
    
    src_mac = pkt[Ether].dst if pkt.haslayer(Ether) else "ff:ff:ff:ff:ff:ff"
    dst_mac = pkt[Ether].src if pkt.haslayer(Ether) else "00:00:00:00:00:00"
    conn_id = (ip_layer.src, tcp_layer.sport, tcp_layer.dport)

    # Clean update pattern to mutate values across process managers securely
    if conn_id not in connection_states:
        connection_states[conn_id] = {'seq': tcp_layer.ack if tcp_layer.ack > 0 else 1000, 'ack': 0}
    state = dict(connection_states[conn_id])

    # Tear down session logs immediately upon detecting active RST or FIN assertions
    if tcp_layer.flags & 0x05:
        if conn_id in connection_states:
            del connection_states[conn_id]
        return

    if pkt.haslayer(Raw):
        raw_payload = pkt[Raw].load
        payload_len = len(raw_payload)
        state['ack'] = tcp_layer.seq + payload_len
        response_payload = b""

        if tcp_layer.dport == 80:
            response_payload = b"HTTP/1.1 200 OK\r\nServer: Microsoft-IIS/10.0\r\nContent-Length: 0\r\n\r\n"
            l7_tracker.log_http_banner(ip_layer.src, "", "Microsoft-IIS/10.0", "Nmap-Probe")
        elif tcp_layer.dport == 3389:
            if raw_payload.startswith(b"\x03\x00\x00"):
                logging.info(f"⚡ RDP Interception confirmed from source: {ip_layer.src}")
                response_payload = b"\x03\x00\x00\x0b\x06\xd0\x00\x00\x12\x34\x00"
                l7_tracker.log_http_banner(ip_layer.src, "rdp_handshake_ok", "MS-RDP-Server", "Nmap-Core")

        if response_payload:
            # Build and inject full Layer 2 frame to preserve custom MAC configurations
            reply_frame = (
                Ether(src=src_mac, dst=dst_mac) /
                IP(src=ip_layer.dst, dst=ip_layer.src) /
                TCP(
                    sport=tcp_layer.dport,
                    dport=tcp_layer.sport,
                    flags="PA",
                    seq=state['seq'],
                    ack=state['ack']
                ) /
                Raw(load=response_payload)
            )
            sendp(reply_frame, iface=nic, verbose=False)
            
            state['seq'] += len(response_payload)
            connection_states[conn_id] = state

def packet_worker(queue, args, host_ip, connection_states, template_dict, pair_dict, shared_fingerprint_proxy):
    """Execution logic running completely within independent worker process regions."""
    # Wire the proxy into the localized response module thread context before starting loops
    response.get_shared_learner(shared_fingerprint_proxy)
    
    while True:
        pkt_data = queue.get()
        if pkt_data is None:
            queue.task_done()
            break
        
        try:
            pkt = Ether(pkt_data)
            if args.scan in ["od", "pd"]:
                handle_l7_deception(pkt, args.nic, connection_states, shared_fingerprint_proxy)
            
            if args.scan == "ts":
                packet_obj = Packet(bytes(pkt))
                packet_obj.interface = args.nic
                packet_obj.unpack()
                proto = packet_obj.l4 if packet_obj.l4 else packet_obj.l3
                
                if proto:
                    templateSynthesis(packet_obj, proto.upper(), template_dict, pair_dict, host_ip, base_path=args.dest, enable_l7=True)
        except Exception as e:
            logging.debug(f"Process Pool Worker Interruption: {e}")
        finally:
            queue.task_done()

def run_sniffing_engine(args, host_ip):
    packet_queue = JoinableQueue(maxsize=10000)
    
    # Initialize unified Manager structures to bridge data models safely across processes
    manager = Manager()
    connection_states = manager.dict()
    template_dict = manager.dict()
    pair_dict = manager.dict()
    shared_fingerprint_proxy = manager.dict()

    # Link the multi-process dictionary maps into our tracking dashboard before boot
    l7_tracker.l7_data = manager.dict()
    l7_tracker.ja3_map = manager.dict()
    l7_tracker.ua_map = manager.dict()

    num_workers = max(1, cpu_count() - 1)
    workers = []
    for i in range(num_workers):
        p = Process(
            target=packet_worker,
            args=(packet_queue, args, host_ip, connection_states, template_dict, pair_dict, shared_fingerprint_proxy),
            name=f"Worker-{i}"
        )
        p.daemon = True
        p.start()
        workers.append(p)

    def producer(pkt):
        try:
            if pkt.haslayer(IP):
                packet_queue.put(bytes(pkt), block=False)
        except:
            pass # Suppress overflow frame drops under high burst sweeps

    logging.info(f"🚀 Multiprocessing Architecture fully operational on interface: {args.nic}")
    
    # Spawn sniffer. If GUI dashboard is requested, put sniffer loop into a daemon thread
    sniffer_timeout = args.te * 60 if args.te else 300
    
    if not args.no_gui:
        sniff_thread = threading.Thread(
            target=lambda: sniff(iface=args.nic, filter="ip", prn=producer, store=False, timeout=sniffer_timeout),
            daemon=True
        )
        sniff_thread.start()
        
        # Blocking call to safely hook the main process thread loop for UI rendering
        l7_tracker.launch_plot()
    else:
        sniff(iface=args.nic, filter="ip", prn=producer, store=False, timeout=sniffer_timeout)

    # Terminate and clean up process pools cleanly upon timeout expiry or interrupt
    for _ in range(num_workers):
        packet_queue.put(None)
    packet_queue.join()

    if args.scan == "ts":
        save_templates(args.dest, template_dict)

def save_templates(dest_path, template_dict):
    os.makedirs(dest_path, exist_ok=True)
    try:
        native_dict = dict(template_dict)
        for proto, records in native_dict.items():
            outdata = {k.hex() if isinstance(k, bytes) else str(k): v.hex() if isinstance(v, bytes) else str(v) for k, v in records.items() if v}
            if outdata:
                out_file = os.path.join(dest_path, f"{str(proto).lower()}_record.txt")
                with open(out_file, "w") as f:
                    json.dump(outdata, f, indent=2)
        logging.info(f"📦 Synthetic signature template data dumped to destination path: {dest_path}")
    except Exception as e:
        logging.error(f"❌ Failed to persist configuration blocks down to disk: {e}")

def set_nic_config(nic):
    try:
        subprocess.run(["ip", "link", "set", nic, "promisc", "on"], check=True)
        logging.info(f"🔁 Link target interface hardware matching vector '{nic}' moved to Promiscuous Mode.")
    except Exception as e:
        logging.warning(f"⚠️ Unable to register promiscuous capabilities on card: {e}")

def get_host_ip(nic):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        res = s.getsockname()[0]
        s.close()
        return res
    except:
        return "127.0.0.1"

def main():
    parser = argparse.ArgumentParser(description="🛡️ High-Performance Stateful Deception Engine")
    parser.add_argument("--scan", choices=["ts", "od", "pd"], required=True)
    parser.add_argument("--host", help="Target Host IP")
    parser.add_argument("--nic", help="Network Interface")
    parser.add_argument("--dest", help="Destination for records")
    parser.add_argument("--os", help="OS to simulate")
    parser.add_argument("--status", help="Port config JSON string")
    parser.add_argument("--te", type=int, default=5, help="Timeout lifecycle tracking clock metric in minutes")
    parser.add_argument("--no-gui", action="store_true", help="Omit the real-time visualization tracker window layout")
    args = parser.parse_args()

    args.nic = args.nic or settings.NIC_PROBE
    args.host = args.host or get_host_ip(args.nic)
    args.dest = args.dest or settings.OS_RECORD_PATH
    
    set_nic_config(args.nic)
    run_sniffing_engine(args, args.host)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logging.info("\n🛑 Secure termination sequence initiated by operator. Exiting.")
        sys.exit(0)
