import os  
import sys  
import time  
import logging  
import argparse  
from datetime import datetime  

# Additional imports for networking  
try:  
    # Use scapy for packet sniffing and sending if available  
    from scapy.all import sniff, send, sendp, ARP, ICMP, IP, TCP, UDP, Ether  
except ImportError:  
    sniff = send = sendp = ARP = ICMP = IP = TCP = UDP = Ether = None  

# Constants  
OS_RECORD_DIR = "/home/user/Camouflage-Cloak/os_record"  
ARP_RECORD_FILE = os.path.join(OS_RECORD_DIR, "arp_record.txt")  
ICMP_RECORD_FILE = os.path.join(OS_RECORD_DIR, "icmp_record.txt")  
TCP_RECORD_FILE = os.path.join(OS_RECORD_DIR, "tcp_record.txt")  
UDP_RECORD_FILE = os.path.join(OS_RECORD_DIR, "udp_record.txt")  
TIMEOUT_SECONDS = 180  # 3 minutes for --scan ts mode  

# Configure logging  
logging.basicConfig(  
    level=logging.INFO,  
    format="%(asctime)s [%(levelname)s] %(message)s",  
    datefmt="%Y-%m-%d %H:%M:%S"  
)  

def check_os_record_files():  
    """Check that OS record directory exists and is accessible."""  
    if not os.path.isdir(OS_RECORD_DIR):  
        logging.error(f"OS record directory not found: {OS_RECORD_DIR}. Please create it and add fingerprint files.")  
        sys.exit(1)  
    if not os.access(OS_RECORD_DIR, os.W_OK):  
        logging.error(f"OS record directory {OS_RECORD_DIR} is not writable.")  
        sys.exit(1)  

def save_fingerprint(arp_data, icmp_data, tcp_data, udp_data):  
    """Save collected fingerprint data to files (overwrites existing content)."""  
    try:  
        with open(ARP_RECORD_FILE, 'w') as f:  
            f.write(arp_data)  
        with open(ICMP_RECORD_FILE, 'w') as f:  
            f.write(icmp_data)  
        with open(TCP_RECORD_FILE, 'w') as f:  
            f.write(tcp_data)  
        with open(UDP_RECORD_FILE, 'w') as f:  
            f.write(udp_data)  
    except Exception as e:  
        logging.error(f"Failed to write fingerprint files: {e}")  
        sys.exit(1)  
    else:  
        logging.info("OS fingerprint data saved to os_record files.")  

def load_fingerprint():  
    """Load fingerprint data from files and return as a dictionary."""  
    fingerprint = {}  
    try:  
        with open(ARP_RECORD_FILE, 'r') as f:  
            fingerprint['arp'] = f.read().strip()  
        with open(ICMP_RECORD_FILE, 'r') as f:  
            fingerprint['icmp'] = f.read().strip().splitlines()  
        with open(TCP_RECORD_FILE, 'r') as f:  
            fingerprint['tcp'] = f.read().strip().splitlines()  
        with open(UDP_RECORD_FILE, 'r') as f:  
            fingerprint['udp'] = f.read().strip()  
    except FileNotFoundError as e:  
        logging.error(f"Fingerprint file not found: {e}. Ensure you have run '--scan ts' or provided the correct path.")  
        sys.exit(1)  
    except Exception as e:  
        logging.error(f"Error reading fingerprint files: {e}")  
        sys.exit(1)  
    return fingerprint  

def run_training_mode():  
    """Capture network packets for 3 minutes to gather OS fingerprint data."""  
    logging.info("Starting OS fingerprint collection (training mode) for 3 minutes...")  
    # Data holders for captured info  
    arp_info = ""  
    icmp_info_lines = []  
    tcp_info_lines = []  
    udp_info = ""  
    open_port = None  

    start_time = time.time()  

    if sniff is None:  
        logging.error("Scapy is required for training mode, but it's not available.")  
        sys.exit(1)  

    # Determine local IP to filter relevant traffic (if possible)  
    from scapy.all import conf  
    my_ip = None  
    try:  
        my_ip = conf.route.route("0.0.0.0")[1]  # get default IP address  
    except Exception as e:  
        logging.warning(f"Could not determine local IP automatically: {e}. Capturing all traffic.")  
    if my_ip:  
        logging.info(f"Local IP for monitoring: {my_ip}")  
    else:  
        logging.info("No specific local IP determined; monitoring all traffic for fingerprint responses.")  

    # Track which responses are seen  
    responses_captured = {  
        'arp_reply': False,  
        'icmp_echo_reply': False,  
        'icmp_timestamp_reply': False,  
        'icmp_netmask_reply': False,  
        'tcp_synack': False,  
        'tcp_rst': False,  
        'udp_unreach': False  
    }  

    def packet_collector(pkt):  
        nonlocal arp_info, udp_info, open_port  
        try:  
            # Capture ARP reply from this host  
            if ARP in pkt and pkt[ARP].op == 2:  # ARP reply  
                if my_ip is None or pkt[ARP].psrc == my_ip:  
                    responses_captured['arp_reply'] = True  
                    raw = bytes(pkt)  
                    pad_len = len(raw) - 42  # ARP packet is 42 bytes without padding (Ethernet+ARP)  
                    padding = raw[-pad_len:] if pad_len > 0 else b''  
                    arp_info = f"ARP reply length: {len(raw)} bytes, padding: {padding.hex() if padding else 'None'}"  
                    logging.info(f"Captured ARP reply: length={len(raw)}, padding={padding.hex() if padding else 'None'}")  

            # Capture outgoing ICMP responses (Echo, Timestamp, Netmask replies)  
            if IP in pkt and ICMP in pkt and (my_ip is None or pkt[IP].src == my_ip):  
                icmp_type = pkt[ICMP].type  
                ip_layer = pkt[IP]  

                if icmp_type == 0:  # Echo Reply  
                    responses_captured['icmp_echo_reply'] = True  
                    ttl = ip_layer.ttl  
                    df = (ip_layer.flags & 2) != 0  # DF flag  
                    tos = ip_layer.tos  
                    icmp_info_lines.append(f"EchoReply: TTL={ttl}, DF={'1' if df else '0'}, TOS=0x{tos:02x}")  
                    logging.info(f"Captured ICMP Echo Reply (TTL={ttl}, DF={'set' if df else 'not set'}, TOS=0x{tos:02x})")  

                elif icmp_type == 14:  # Timestamp Reply  
                    responses_captured['icmp_timestamp_reply'] = True  
                    ttl = ip_layer.ttl  
                    df = (ip_layer.flags & 2) != 0  
                    icmp_info_lines.append(f"TimestampReply: TTL={ttl}, DF={'1' if df else '0'}")  
                    logging.info(f"Captured ICMP Timestamp Reply (TTL={ttl}, DF={'set' if df else 'not set'})")  

                elif icmp_type == 18:  # Address Mask Reply  
                    responses_captured['icmp_netmask_reply'] = True  
                    ttl = ip_layer.ttl  
                    df = (ip_layer.flags & 2) != 0  
                    icmp_info_lines.append(f"NetmaskReply: TTL={ttl}, DF={'1' if df else '0'}")  
                    logging.info(f"Captured ICMP Address Mask Reply (TTL={ttl}, DF={'set' if df else 'not set'})")  

                # Capture ICMP Port Unreachable (for UDP closed port responses)  
                if icmp_type == 3 and (pkt[ICMP].code == 3):  # Type=3 (Destination Unreachable), Code=3 (Port Unreachable)  
                    responses_captured['udp_unreach'] = True  
                    ttl = ip_layer.ttl  
                    df = (ip_layer.flags & 2) != 0  
                    # Determine how many bytes of original payload were included in the ICMP  
                    inner_ip = pkt[ICMP].payload  # this is the encapsulated original packet  
                    included_bytes = len(bytes(inner_ip)) if inner_ip else 0  
                    udp_info = f"ICMP Unreachable: TTL={ttl}, DF={'1' if df else '0'}, included_bytes={included_bytes}"  
                    logging.info(f"Captured ICMP Port Unreachable (TTL={ttl}, DF={'set' if df else 'not set'}, included_bytes={included_bytes})")  

            # Capture TCP responses (SYN-ACK from open port, RST from closed port)  
            if IP in pkt and TCP in pkt and (my_ip is None or pkt[IP].src == my_ip):  
                tcp_layer = pkt[TCP]  
                ip_layer = pkt[IP]  
                flags = tcp_layer.flags  
                ttl = ip_layer.ttl  
                df = (ip_layer.flags & 2) != 0  

                if flags == "SA":  # SYN-ACK (open port response)  
                    responses_captured['tcp_synack'] = True  
                    open_port = tcp_layer.sport  # the port on this host that responded  
                    window = tcp_layer.window  
                    options = tcp_layer.options  
                    opt_str = ",".join([opt[0] if isinstance(opt, tuple) else str(opt) for opt in options]) if options else "None"  
                    tcp_info_lines.append(f"SYN-ACK port {open_port}: TTL={ttl}, DF={'1' if df else '0'}, WIN={window}, OPTS={opt_str}")  
                    logging.info(f"Captured TCP SYN-ACK from port {open_port} (TTL={ttl}, DF={'set' if df else 'not set'}, WIN={window}, OPTS={opt_str})")  

                elif "R" in flags and "S" not in flags:  # RST (likely to a closed port probe)  
                    responses_captured['tcp_rst'] = True  
                    window = tcp_layer.window  
                    tcp_info_lines.append(f"RST: TTL={ttl}, DF={'1' if df else '0'}, WIN={window}")  
                    logging.info(f"Captured TCP RST (TTL={ttl}, DF={'set' if df else 'not set'}, WIN={window})")  

        except Exception as e:  
            logging.error(f"Error in packet_collector: {e}")  

    # Sniff for the specified duration  
    bpf_filter = "arp"  
    if my_ip:  
        bpf_filter += f" or host {my_ip}"  
    try:  
        sniff(filter=bpf_filter, prn=packet_collector, store=0, timeout=TIMEOUT_SECONDS)  
    except Exception as e:  
        logging.error(f"Sniffing error: {e}. Ensure you have proper permissions (run as root).")  
        sys.exit(1)  

    elapsed = time.time() - start_time  
    logging.info(f"Packet capture completed (duration: {elapsed:.1f} seconds). Processing results...")  

    # Mark missing responses (for completeness of records)  
    if not responses_captured['arp_reply']:  
        arp_info = "No ARP reply captured"  
        logging.info("No ARP reply was captured during training.")  
    if not responses_captured['icmp_echo_reply']:  
        icmp_info_lines.append("No Echo Reply")  
        logging.info("No ICMP Echo Reply was captured during training.")  
    if not responses_captured['icmp_timestamp_reply']:  
        icmp_info_lines.append("No Timestamp Reply")  
        logging.info("No ICMP Timestamp Reply was captured during training.")  
    if not responses_captured['icmp_netmask_reply']:  
        icmp_info_lines.append("No Netmask Reply")  
        logging.info("No ICMP Netmask Reply was captured during training.")  
    if not responses_captured['udp_unreach']:  
        udp_info = "No ICMP Unreachable captured"  
        logging.info("No ICMP Port Unreachable (UDP) was captured during training.")  
    if not responses_captured['tcp_synack']:  
        tcp_info_lines.append("No SYN-ACK (open port) captured")  
        logging.info("No TCP SYN-ACK (open port response) was captured during training.")  
    if not responses_captured['tcp_rst']:  
        tcp_info_lines.append("No RST (closed port) captured")  
        logging.info("No TCP RST (closed port response) was captured during training.")  

    # Prepare data strings for saving  
    arp_text = arp_info + "\n"  
    icmp_text = "\n".join(icmp_info_lines) + "\n"  
    tcp_text = "\n".join(tcp_info_lines) + "\n"  
    udp_text = udp_info + "\n"  

    save_fingerprint(arp_text, icmp_text, tcp_text, udp_text)  
    logging.info("Training mode completed. OS fingerprint files have been updated.")  

def run_deception_mode(os_name, te_arg):  
    """Run OS deception mode using the loaded fingerprint data."""  
    logging.info(f"Starting OS deception mode (Emulating OS: {os_name})")  
    if sniff is None or send is None or sendp is None:  
        logging.error("Scapy is required for deception mode, but it's not available.")  
        sys.exit(1)  

    # Load previously recorded fingerprint data  
    fp = load_fingerprint()  
    arp_data = fp.get('arp', '')  
    icmp_lines = fp.get('icmp', [])  
    tcp_lines = fp.get('tcp', [])  
    udp_data = fp.get('udp', '')  

    # Determine which ICMP replies to send based on fingerprint  
    respond_timestamp = any("TimestampReply" in line for line in icmp_lines)  
    respond_netmask = any("NetmaskReply" in line for line in icmp_lines)  
    # Get Echo Reply parameters (TTL, DF)  
    echo_ttl = 64  
    echo_df = True  
    for line in icmp_lines:  
        if line.startswith("EchoReply"):  
            # Example line: "EchoReply: TTL=128, DF=0, TOS=0x00"  
            parts = line.replace(" ", "").split(',')  
            for part in parts:  
                if part.startswith("TTL="):  
                    echo_ttl = int(part.split("=")[1])  
                if part.startswith("DF="):  
                    echo_df = (part.split("=")[1] == '1')  
            break  

    # Get UDP unreachable response parameters  
    udp_ttl = 64  
    udp_df = True  
    if udp_data.startswith("ICMP Unreachable"):  
        # Example: "ICMP Unreachable: TTL=64, DF=1, included_bytes=8"  
        try:  
            udp_ttl = int(udp_data.split("TTL=")[1].split(",")[0])  
            udp_df = (udp_data.split("DF=")[1].split(",")[0].strip() == '1')  
        except Exception:  
            pass  

    # Get TCP RST parameters (TTL, DF, WIN)  
    rst_ttl = 64  
    rst_df = True  
    rst_win = 0  
    for line in tcp_lines:  
        if line.startswith("RST"):  
            try:  
                rst_ttl = int(line.split("TTL=")[1].split(",")[0])  
                rst_df = (line.split("DF=")[1].split(",")[0].strip() == '1')  
                rst_win = int(line.split("WIN=")[1])  
            except Exception:  
                pass  
            break  

    # Get TCP SYN-ACK (open port) parameters  
    open_port = None  
    synack_ttl = 64  
    synack_df = True  
    synack_win = 0  
    synack_opts = []  
    for line in tcp_lines:  
        if line.startswith("SYN-ACK"):  
            # Example: "SYN-ACK port 22: TTL=64, DF=1, WIN=64240, OPTS=MSS,SAckOK,TS"  
            try:  
                # Extract port number  
                port_part = line.split("port")[1]  
                open_port = int(port_part.split(":")[0].strip())  
                synack_ttl = int(line.split("TTL=")[1].split(",")[0])  
                synack_df = (line.split("DF=")[1].split(",")[0].strip() == '1')  
                synack_win = int(line.split("WIN=")[1].split(",")[0])  
                if "OPTS=" in line:  
                    opts_str = line.split("OPTS=")[1]  
                    synack_opts = [opt.strip() for opt in opts_str.split(",") if opt.strip()]  
            except Exception:  
                pass  
            break  

    if open_port:  
        logging.info(f"Pretending port {open_port} is open based on fingerprint.")  
    else:  
        logging.info("No open port fingerprint found; no SYN-ACK will be emulated for any port.")  

    # Prepare ARP padding bytes if any were recorded (to mimic ARP frame length)  
    arp_padding = b''  
    if arp_data and "padding:" in arp_data:  
        pad_hex = arp_data.split("padding:")[1].strip()  
        if pad_hex and pad_hex.lower() != 'none':  
            try:  
                arp_padding = bytes.fromhex(pad_hex)  
            except Exception as e:  
                logging.warning(f"Could not parse ARP padding from recorded data: {e}")  

    # Determine our IP (for sniff filter and response crafting)  
    try:  
        from scapy.all import conf  
        my_ip = conf.route.route("0.0.0.0")[1]  
    except Exception:  
        my_ip = None  

    def deceive_packet(pkt):  
        # Handle ARP requests for our IP (forge ARP replies)  
        if ARP in pkt and pkt[ARP].op == 1:  # who-has (ARP request)  
            target_ip = pkt[ARP].pdst  
            if (my_ip and target_ip != my_ip):  
                return  # Not for us  
            src_ip = pkt[ARP].psrc  
            src_mac = pkt[ARP].hwsrc  
            logging.info(f"Received ARP request from {src_ip} ({src_mac}) for {target_ip}. Sending spoofed ARP reply.")  
            # Forge ARP reply with our (forged) MAC and the requested IP  
            try:  
                from scapy.all import get_if_hwaddr, conf as scapy_conf  
                my_mac = get_if_hwaddr(scapy_conf.iface)  # our actual MAC on default interface  
            except Exception:  
                my_mac = pkt[ARP].hwdst or "00:00:00:00:00:00"  
            arp_reply = ARP(op=2, hwsrc=my_mac, psrc=target_ip, hwdst=src_mac, pdst=src_ip)  
            ether = Ether(src=my_mac, dst=src_mac)  
            reply_pkt = ether / arp_reply  
            raw_reply = bytes(reply_pkt)  
            # Apply recorded padding pattern if available  
            if arp_padding and len(raw_reply) >= 60:  
                pad_len = len(raw_reply) - 42  
                if pad_len == len(arp_padding):  
                    raw_reply = raw_reply[:42] + arp_padding  
            sendp(raw_reply, verbose=False)  

        # Handle IP-based probes (ICMP and TCP)  
        if IP in pkt:  
            ip_pkt = pkt[IP]  
            src_ip = ip_pkt.src  
            dst_ip = ip_pkt.dst  
            if my_ip and dst_ip != my_ip:  
                return  # Packet not directed to us, ignore  
            # If target_env (te_arg) is specified, optionally filter by source  
            if te_arg:  
                try:  
                    if src_ip != te_arg:  
                        return  
                except Exception:  
                    pass  

            # ICMP probes  
            if ICMP in pkt:  
                icmp_req = pkt[ICMP]  
                if icmp_req.type == 8:  # Echo Request  
                    logging.info(f"Received ICMP Echo Request from {src_ip}. Sending spoofed Echo Reply.")  
                    ip_reply = IP(src=dst_ip, dst=src_ip, ttl=echo_ttl)  
                    if echo_df:  
                        ip_reply.flags |= 2  # set DF flag  
                    # Echo reply: type=0, code=0, echo the ID and seq  
                    icmp_reply = ICMP(type=0, code=0, id=icmp_req.id, seq=icmp_req.seq)  
                    # Copy payload from request, if any  
                    reply_payload = bytes(icmp_req.payload)  
                    reply_pkt = ip_reply / icmp_reply / reply_payload  
                    send(reply_pkt, verbose=False)  

                elif icmp_req.type == 13 and respond_timestamp:  # Timestamp Request  
                    logging.info(f"Received ICMP Timestamp Request from {src_ip}. Sending spoofed Timestamp Reply.")  
                    ip_reply = IP(src=dst_ip, dst=src_ip, ttl=echo_ttl)  
                    if echo_df:  
                        ip_reply.flags |= 2  
                    # Construct Timestamp Reply (type=14) with same ID/seq  
                    icmp_reply = ICMP(type=14, id=icmp_req.id, seq=icmp_req.seq)  
                    # Echo the originate timestamp, and set receive/transmit to current time  
                    orig_ts = icmp_req.ts_ori  
                    now_ts = (int(time.time() * 1000) & 0xFFFFFFFF)  # current time in ms (mod 32-bit)  
                    icmp_reply.ts_ori = orig_ts  
                    icmp_reply.ts_rx = now_ts  
                    icmp_reply.ts_tx = now_ts  
                    reply_pkt = ip_reply / icmp_reply  
                    send(reply_pkt, verbose=False)  

                elif icmp_req.type == 17 and respond_netmask:  # Address Mask Request  
                    logging.info(f"Received ICMP Address Mask Request from {src_ip}. Sending spoofed Address Mask Reply.")  
                    ip_reply = IP(src=dst_ip, dst=src_ip, ttl=echo_ttl)  
                    if echo_df:  
                        ip_reply.flags |= 2  
                    icmp_reply = ICMP(type=18, id=icmp_req.id, seq=icmp_req.seq)  
                    # Provide a default subnet mask (e.g., 255.255.255.0)  
                    icmp_reply_payload = b'\xff\xff\xff\x00'  
                    reply_pkt = ip_reply / icmp_reply / icmp_reply_payload  
                    send(reply_pkt, verbose=False)  

            # TCP probes  
            if TCP in pkt:  
                tcp_pkt = pkt[TCP]  
                flags = tcp_pkt.flags  
                src_port = tcp_pkt.sport  
                dst_port = tcp_pkt.dport  

                if flags == "S":  # SYN packet  
                    if open_port and dst_port == open_port:  
                        # SYN to the port we are emulating as open  
                        logging.info(f"Received TCP SYN from {src_ip} to port {open_port}. Sending spoofed SYN-ACK.")  
                        ip_reply = IP(src=dst_ip, dst=src_ip, ttl=synack_ttl)  
                        if synack_df:  
                            ip_reply.flags |= 2  
                        # Craft SYN-ACK with similar window and options  
                        import random  
                        seq_num = random.randint(0, 0xFFFFFFFF)  
                        ack_num = tcp_pkt.seq + 1  
                        tcp_reply = TCP(sport=dst_port, dport=src_port, flags="SA", seq=seq_num, ack=ack_num, window=synack_win)  
                        # Reconstruct TCP options as recorded  
                        opts = []  
                        for opt in synack_opts:  
                            if opt == 'MSS':  
                                opts.append(('MSS', 1460))  # typical MSS (could refine if original had different)  
                            elif opt == 'SAckOK':  
                                opts.append(('SAckOK', b''))  
                            elif opt.startswith('WS'):  # e.g., "WS" or "WS=8" for window scale  
                                scale = 0  
                                if '=' in opt:  
                                    try:  
                                        scale = int(opt.split('=')[1])  
                                    except:  
                                        scale = 0  
                                opts.append(('WScale', scale))  
                            elif opt == 'TS':  
                                now_ts = (int(time.time() * 1000) & 0xFFFFFFFF)  
                                opts.append(('Timestamp', (now_ts, 0)))  
                            elif opt == 'NOP':  
                                opts.append(('NOP', None))  
                        if opts:  
                            tcp_reply.options = opts  
                        reply_pkt = ip_reply / tcp_reply  
                        send(reply_pkt, verbose=False)  

                    else:  
                        # SYN to a port we consider closed  
                        logging.info(f"Received TCP SYN from {src_ip} to closed port {dst_port}. Sending spoofed RST.")  
                        ip_reply = IP(src=dst_ip, dst=src_ip, ttl=rst_ttl)  
                        if rst_df:  
                            ip_reply.flags |= 2  
                        # RST in response to SYN (send ACK to acknowledge SYN)  
                        seq_num = 0  
                        ack_num = tcp_pkt.seq + 1  
                        tcp_reply = TCP(sport=dst_port, dport=src_port, flags="R", seq=seq_num, ack=ack_num, window=rst_win)  
                        send(ip_reply / tcp_reply, verbose=False)  

                elif flags == "A" and open_port and dst_port == open_port:  
                    # ACK to our SYN-ACK (handshake completion)  
                    logging.info(f"Received ACK from {src_ip} on port {open_port}. Sending RST to close handshake.")  
                    ip_reply = IP(src=dst_ip, dst=src_ip, ttl=synack_ttl)  
                    if synack_df:  
                        ip_reply.flags |= 2  
                    seq_num = tcp_pkt.ack  # their next expected seq  
                    ack_num = tcp_pkt.seq + 1  
                    tcp_reply = TCP(sport=dst_port, dport=src_port, flags="R", seq=seq_num, ack=ack_num, window=synack_win)  
                    send(ip_reply / tcp_reply, verbose=False)  

                elif "F" in flags and open_port and dst_port == open_port:  
                    # FIN probe to open port (some OS send RST for an unsolicited FIN)  
                    logging.info(f"Received FIN from {src_ip} on open port {open_port}. Sending RST as per fingerprint.")  
                    ip_reply = IP(src=dst_ip, dst=src_ip, ttl=synack_ttl)  
                    if synack_df:  
                        ip_reply.flags |= 2  
                    seq_num = tcp_pkt.ack if "A" in flags else 0  
                    ack_num = tcp_pkt.seq + (1 if "F" in flags else 0)  
                    tcp_reply = TCP(sport=dst_port, dport=src_port, flags="R", seq=seq_num, ack=ack_num, window=synack_win)  
                    send(ip_reply / tcp_reply, verbose=False)  

    # Set capture filter for deception mode  
    bpf_filter = "arp"  
    if my_ip:  
        bpf_filter += f" or host {my_ip}"  

    logging.info("Camouflage Cloak is now active. Awaiting incoming probes...")  
    try:  
        sniff(filter=bpf_filter, prn=deceive_packet, store=0)  
    except KeyboardInterrupt:  
        logging.info("OS deception mode stopped by user (Ctrl-C).")  
    except Exception as e:  
        logging.error(f"Error during deception mode sniffing: {e}")  
        sys.exit(1)  

# Parse command-line arguments  
parser = argparse.ArgumentParser(description="Camouflage Cloak - OS Fingerprint Camouflage Tool")  
parser.add_argument('--scan', choices=['ts', 'od'], required=True, help='Scan mode: ts (training/collect), od (OS deception)')  
parser.add_argument('--os', dest='os_name', help='Operating system name to emulate (required for --scan od)')  
parser.add_argument('--te', dest='target_env', help='Target environment parameter (e.g., target IP or identifier for filtering)')  
args = parser.parse_args()  

# Ensure the OS record directory exists and is accessible  
check_os_record_files()  

# Run the chosen mode  
if args.scan == 'ts':  
    # Training mode (no --os or --te needed)  
    run_training_mode()  
elif args.scan == 'od':  
    if args.os_name is None:  
        logging.error("The --os argument is required when using --scan od (specify an OS to emulate).")  
        sys.exit(1)  
    run_deception_mode(args.os_name, args.target_env)  
