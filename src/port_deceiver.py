import logging
from scapy.all import IP, TCP, send  # plus any other scapy components used for packet crafting
from settings import get_os_fingerprint

logger = logging.getLogger(__name__)
# (Assume logging is configured in the main program to capture these logs appropriately)

class PortDeceiver:
    """
    PortDeceiver simulates open/closed ports with spoofed OS fingerprints to deceive port scanners.
    It crafts TCP/IP responses (e.g., SYN-ACK or RST packets) with characteristics matching a target OS.
    """
    def __init__(self, interface_ip, os_name=None, ports_config=None):
        """
        Initialize the PortDeceiver.
        :param interface_ip: The IP address of the interface to use for crafting replies.
        :param os_name: Name of the OS whose fingerprint to mimic (can be None for default).
        :param ports_config: Configuration of ports to simulate (e.g., which ports appear open or closed).
        """
        self.local_ip = interface_ip
        self.os_name = os_name
        self.ports_config = ports_config or {}  # e.g., dict of port->state ('open' or 'closed'), if applicable

        # Retrieve OS fingerprint traits (TTL, window, etc.) using settings.get_os_fingerprint
        fingerprint = None
        if self.os_name:
            fingerprint = get_os_fingerprint(self.os_name)
        if not fingerprint:
            # OS not recognized or not provided – use safe fallback defaults
            if self.os_name:
                logger.warning(f"Unknown OS '{self.os_name}' – using fallback TTL=64, window=8192.")
            else:
                logger.info("No OS specified – using default TTL=64, window=8192.")
            fingerprint = {'ttl': 64, 'window': 8192}
        else:
            # Fingerprint found for the given OS name (or alias)
            # Log which OS template is being used, including alias resolution if applicable
            os_name_lower = self.os_name.lower() if self.os_name else ""
            # Define common aliases for logging purposes
            alias_map = {
                "winxp": "Windows XP", "windows xp": "Windows XP",
                "win7": "Windows 7", "windows 7": "Windows 7",
                "win8": "Windows 8", "windows 8": "Windows 8",
                "win10": "Windows 10", "windows 10": "Windows 10",
                "win11": "Windows 11", "windows 11": "Windows 11",
                "macos": "Mac OS X", "osx": "Mac OS X"
            }
            if os_name_lower in alias_map:
                # The provided name is an alias that was resolved internally
                actual_name = alias_map[os_name_lower]
                logger.info(f"OS alias '{self.os_name}' resolved to '{actual_name}' – using OS fingerprint (TTL={fingerprint['ttl']}, window={fingerprint['window']}).")
            else:
                # Use the provided OS name in the log (already a canonical name or unrecognized alias that happened to match)
                logger.info(f"Using OS fingerprint for '{self.os_name}' (TTL={fingerprint['ttl']}, window={fingerprint['window']}).")

        # Save the fingerprint parameters for use in packet crafting
        self.default_ttl = fingerprint.get('ttl', 64)
        self.default_window = fingerprint.get('window', 8192)
        # Other traits like Don't-Fragment flag, TCP options (e.g., timestamp, window scale) can be included if provided
        self.df_flag = fingerprint.get('df', False)               # Don't Fragment flag (DF) default
        self.win_scale = fingerprint.get('wscale', 0)             # Window scale factor (if any; 0 means no scaling)
        self.mss_value = fingerprint.get('mss', 1460)             # MSS value for TCP options (1460 is common default)
        self.timestamp_enabled = fingerprint.get('timestamp', False) or fingerprint.get('ts', False)
        # Note: The get_os_fingerprint may return more fields depending on implementation, e.g., options list.

        # Initialize any necessary state for tracking ongoing deceptive connections
        self.sessions = {}  # e.g., {(client_ip, client_port, server_port): connection_state}

    def craft_response(self, src_ip, src_port, dst_port, flag):
        """
        Craft a TCP packet response with the appropriate OS fingerprint.
        :param src_ip: Source IP of the incoming packet (the scanner's IP).
        :param src_port: Source port of the incoming packet.
        :param dst_port: Destination port that was targeted (our port).
        :param flag: The TCP flag of the incoming packet ('S' for SYN, etc.).
        :return: Scapy packet (IP/TCP) ready to send, or None if no response needed.
        """
        # Only handle TCP SYN packets for port deception (if other flags, return None)
        if flag != 'S':  # Only respond to SYNs (simplified check)
            return None

        # Determine if the targeted port is supposed to appear open or closed
        port_state = self.ports_config.get(dst_port, 'closed')
        # Create IP/TCP packet with appropriate fingerprint values
        ip_layer = IP(src=self.local_ip, dst=src_ip)
        ip_layer.ttl = self.default_ttl
        if self.df_flag:
            ip_layer.flags |= 0x2  # Set the DF (Don't Fragment) flag in IP if required

        # Build TCP layer
        if port_state == 'open':
            # Simulate open port: respond with SYN-ACK
            tcp_layer = TCP(sport=dst_port, dport=src_port, flags='SA', window=self.default_window)
        else:
            # Simulate closed port: respond with RST
            tcp_layer = TCP(sport=dst_port, dport=src_port, flags='R', window=self.default_window)

        # Apply TCP options for timestamps, window scaling, MSS, etc., if the OS fingerprint requires them
        options = []
        # MSS option (common for SYN-ACK responses)
        if self.mss_value:
            options.append(('MSS', self.mss_value))
        # Window scale option
        if self.win_scale:
            options.append(('WScale', self.win_scale))
        # Timestamp option if enabled
        if self.timestamp_enabled:
            # For a SYN-ACK, set TSval to a pseudo uptime tick and TS ecr (echo) to 0 (no TS in initial SYN)
            import time
            ts_val = int(time.time() * 1000) & 0xFFFFFFFF  # example: millisecond uptime modulo 32-bit
            options.append(('Timestamp', (ts_val, 0)))
        # SACK permitted option (commonly enabled on modern OS)
        if 'MSS' in [opt[0] for opt in options] and self.timestamp_enabled:
            # If MSS is set and timestamp is enabled, often SACK is also permitted
            options.append(('SAckOK', ''))
        tcp_layer.options = options

        return ip_layer / tcp_layer

    def run(self):
        """
        Main loop of the PortDeceiver. It listens for incoming TCP SYN packets on the specified interface/IP 
        and responds with crafted packets that imitate the chosen OS characteristics.
        """
        # This pseudocode assumes a sniffer captures packets directed to this host.
        # In practice, you might use scapy.sniff with a BPF filter for TCP SYNs to our ports.
        # For each captured packet, determine if/how to respond.
        def _packet_handler(packet):
            # Ensure it's an IPv4 TCP packet directed to us
            if packet.haslayer(TCP) and packet.haslayer(IP):
                ip = packet[IP]
                tcp = packet[TCP]
                # Only consider packets destined to our host IP and one of the configured ports
                if ip.dst == self.local_ip:
                    resp = self.craft_response(src_ip=ip.src, src_port=tcp.sport, dst_port=tcp.dport, flag=tcp.flags)
                    if resp:
                        send(resp, verbose=False)
                        # Update state if this was part of a simulated open connection
                        if tcp.flags == 'S':
                            if self.ports_config.get(tcp.dport, 'closed') == 'open':
                                # Record that we've sent a SYN-ACK and are expecting an ACK (simple state tracking)
                                self.sessions[(ip.src, tcp.sport, tcp.dport)] = {'state': 'SYN-ACK sent', 'ts_val': None}
                        if tcp.flags == 'A' and (ip.src, tcp.sport, tcp.dport) in self.sessions:
                            # Received final ACK of 3-way handshake for an open port
                            self.sessions[(ip.src, tcp.sport, tcp.dport)]['state'] = 'established'
                            if self.timestamp_enabled:
                                # Store the peer's echoed timestamp for future timestamp calculations (if needed)
                                self.sessions[(ip.src, tcp.sport, tcp.dport)]['ts_val'] = tcp.options  # simplification

        # Start sniffing for incoming packets (this will run indefinitely in this thread)
        # Using a filter to capture SYN or ACK packets destined to our host on TCP
        try:
            from scapy.all import sniff
            sniff(filter=f"tcp and host {self.local_ip}", prn=_packet_handler, store=False)
        except Exception as e:
            logger.error(f"PortDeceiver sniffing error: {e}")
