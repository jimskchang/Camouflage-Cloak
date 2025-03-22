# port_deceiver.py
"""
port_deceiver.py - Camouflage Cloak Project  
Intercepts inbound TCP probes on closed ports and sends deceptive responses 
to mislead port scanners, using OS-specific network parameters.
"""
import logging
import socket
import struct
import random

from src import settings
from src.tcp import TcpConnect  # Assuming TcpConnect is defined in src.tcp (or possibly src.network)
# Note: If TcpConnect is in another module (e.g., src.network), import accordingly.

# Module logger
logger = logging.getLogger(__name__)

class PortDeceiver:
    def __init__(self, os_name=None):
        """
        Initialize the PortDeceiver.
        :param os_name: Name of the OS to mimic (should have corresponding template in settings.OS_TEMPLATES).
        """
        self.os_name = os_name
        # Set OS-specific parameters (TTL and TCP window) from template if available
        default_ttl = 64
        default_win = 0
        if self.os_name:
            if self.os_name in settings.OS_TEMPLATES:
                tmpl = settings.OS_TEMPLATES[self.os_name]
                self.ttl = tmpl.get('ttl', default_ttl)
                self.win = tmpl.get('tcp_window', default_win)
            else:
                logger.warning("OS template for '%s' not found. Using default TTL and window.", self.os_name)
                self.os_name = None
                self.ttl = default_ttl
                self.win = default_win
        else:
            # No specific OS mimic provided, use default values (likely host defaults)
            self.ttl = default_ttl
            self.win = default_win
        # Initialize raw TCP socket for sending deceptive packets on the designated interface
        try:
            # Use NIC_PROBE for outbound deception traffic
            self.tcp_conn = TcpConnect(nic=settings.NIC_PROBE)
        except Exception as e:
            logger.error("Failed to initialize deception socket on %s: %s", settings.NIC_PROBE, e)
            raise
        # Log initialization details
        logger.info("PortDeceiver initialized on interface %s [OS mimic: %s, TTL: %d, TCP_WINDOW: %d]",
                    settings.NIC_PROBE, self.os_name if self.os_name else "None", self.ttl, self.win)

    def _compute_ip_checksum(self, ip_header: bytes) -> int:
        """
        Compute the IPv4 header checksum. ip_header should have the checksum field set to 0.
        """
        total = 0
        # Add 16-bit words
        length = len(ip_header)
        # If length is odd, pad with one byte (although IP header length should always be even)
        if length % 2:
            ip_header += b'\x00'
            length += 1
        for i in range(0, length, 2):
            word = (ip_header[i] << 8) + ip_header[i+1]
            total += word
            total &= 0xFFFFFFFF  # maintain 32-bit sum
        # Fold to 16 bits
        while total >> 16:
            total = (total & 0xFFFF) + (total >> 16)
        checksum = ~total & 0xFFFF
        return checksum

    def _compute_tcp_checksum(self, ip_src: bytes, ip_dst: bytes, tcp_header: bytes, payload: bytes = b"") -> int:
        """
        Compute the TCP checksum for a given TCP header and payload, using the pseudo-header with IPs.
        The TCP header should have the checksum field set to 0 for computation.
        """
        proto = 6  # TCP protocol number
        tcp_length = len(tcp_header) + len(payload)
        # Pseudo-header: source IP, dest IP, reserved byte, protocol, TCP length
        pseudo_header = ip_src + ip_dst + struct.pack('!BBH', 0, proto, tcp_length)
        total = 0
        # Combine pseudo-header, TCP header, and payload for checksum
        checksum_data = pseudo_header + tcp_header + payload
        if len(checksum_data) % 2:  # pad to even length
            checksum_data += b'\x00'
        for i in range(0, len(checksum_data), 2):
            word = (checksum_data[i] << 8) + checksum_data[i+1]
            total += word
            total &= 0xFFFFFFFF
        # Fold 32-bit sum to 16 bits
        while total >> 16:
            total = (total & 0xFFFF) + (total >> 16)
        checksum = ~total & 0xFFFF
        return checksum

    def process_packet(self, packet_data: bytes) -> bool:
        """
        Process an inbound packet (raw bytes) and send a deceptive TCP response if it matches a reconnaissance probe.
        Returns True if a deceptive response was sent (meaning the original packet should be dropped), False otherwise.
        """
        # Verify packet is long enough for an IPv4 header
        if len(packet_data) < 20:
            return False
        # Parse IPv4 header
        first_byte = packet_data[0]
        version = first_byte >> 4
        if version != 4:
            # Only handle IPv4
            return False
        ihl = first_byte & 0xF
        ip_header_len = ihl * 4
        if len(packet_data) < ip_header_len + 20:
            # Not enough data for TCP header
            return False
        proto = packet_data[9]
        if proto != 6:
            # Not a TCP packet
            return False
        # Extract addresses and ports
        src_ip_bytes = packet_data[12:16]
        dst_ip_bytes = packet_data[16:20]
        src_ip = socket.inet_ntoa(src_ip_bytes)
        dst_ip = socket.inet_ntoa(dst_ip_bytes)
        tcp_start = ip_header_len
        if len(packet_data) < tcp_start + 20:
            # Not enough data for minimum TCP header
            return False
        src_port = int.from_bytes(packet_data[tcp_start:tcp_start+2], 'big')
        dst_port = int.from_bytes(packet_data[tcp_start+2:tcp_start+4], 'big')
        seq_num = int.from_bytes(packet_data[tcp_start+4:tcp_start+8], 'big')
        ack_num = int.from_bytes(packet_data[tcp_start+8:tcp_start+12], 'big')
        flags_byte = packet_data[tcp_start+13]
        # Compute TCP payload length
        total_length = int.from_bytes(packet_data[2:4], 'big')
        tcp_header_len = (packet_data[tcp_start+12] >> 4) * 4
        tcp_payload_length = total_length - ip_header_len - tcp_header_len
        if tcp_payload_length < 0:
            tcp_payload_length = 0
        # Log the incoming packet details at debug level
        flags = []
        if flags_byte & 0x02: flags.append("SYN")
        if flags_byte & 0x10: flags.append("ACK")
        if flags_byte & 0x01: flags.append("FIN")
        if flags_byte & 0x04: flags.append("RST")
        if flags_byte & 0x08: flags.append("PSH")
        if flags_byte & 0x20: flags.append("URG")
        if not flags:
            flags.append("NONE")
        flag_str = ",".join(flags)
        logger.debug("Received packet: %s:%d -> %s:%d [Flags=%s, Seq=%d, Ack=%d, PayloadLen=%d]",
                     src_ip, src_port, dst_ip, dst_port, flag_str, seq_num, ack_num, tcp_payload_length)
        # Check if port is excluded from deception (e.g., real service ports)
        no_deception = getattr(settings, "NO_DECEPTION_PORTS", [])
        if dst_port in no_deception:
            logger.debug("Port %d is a real service/allowed port - not sending deceptive response.", dst_port)
            return False
        # Only handle packets that are not part of an existing legitimate connection
        # RST packets: ignore (no response)
        if flags_byte & 0x04:
            return False
        send_response = False
        resp_seq = 0
        resp_ack = 0
        resp_flags = 0
        # SYN probe: SYN set, ACK not set
        if (flags_byte & 0x02) and not (flags_byte & 0x10):
            # Port likely closed (no service), send RST+ACK to signal closed port
            resp_flags = 0x14  # RST(0x04) + ACK(0x10)
            resp_seq = 0
            # ACK = client seq + payload + 1 (for SYN)
            resp_ack = seq_num + tcp_payload_length + 1
            send_response = True
            logger.info("SYN probe to closed port %d from %s:%d -> sending fake RST/ACK", dst_port, src_ip, src_port)
        # ACK probe: ACK set, SYN not set
        elif (flags_byte & 0x10) and not (flags_byte & 0x02):
            # Port may be open or closed, respond with RST either way (no connection exists for stray ACK)
            resp_flags = 0x04  # RST only
            resp_seq = ack_num  # sequence for RST = incoming ACK (per RFC if ACK set in incoming)
            resp_ack = 0
            send_response = True
            logger.info("ACK probe to port %d from %s:%d -> sending fake RST", dst_port, src_ip, src_port)
        # FIN/Xmas/Null probe: no SYN, no ACK
        elif not (flags_byte & 0x10) and not (flags_byte & 0x02):
            # Windows OS stacks don't respond to these on closed ports - mimic that if needed
            if self.os_name and self.os_name.lower().startswith("win"):
                logger.info("FIN/NULL/Xmas probe to port %d from %s:%d -> mimicking Windows (no response)", dst_port, src_ip, src_port)
                return True  # handled (drop packet, no response)
            else:
                # Other OS: send RST+ACK
                resp_flags = 0x14  # RST + ACK
                resp_seq = 0
                # ACK = seq + payload + (1 if FIN flagged)
                add_seq = 1 if (flags_byte & 0x01) else 0
                resp_ack = seq_num + tcp_payload_length + add_seq
                send_response = True
                logger.info("FIN/NULL/Xmas probe to port %d from %s:%d -> sending fake RST/ACK", dst_port, src_ip, src_port)
        else:
            # Packet doesn't match a port scan pattern we handle
            return False
        if not send_response:
            # No response needed or already handled
            return False
        # Construct IP header for response
        ip_src = dst_ip_bytes  # our IP (original dest)
        ip_dst = src_ip_bytes  # target IP (original source)
        ip_ver_ihl = (4 << 4) | 5
        ip_tos = 0
        ip_len = 20 + 20  # IP header + TCP header (no payload)
        ip_id = random.randrange(0, 65536)
        ip_flags_off = 0
        ip_ttl = self.ttl
        ip_proto = 6
        ip_chk = 0
        ip_header = struct.pack('!BBHHHBBH4s4s',
                                ip_ver_ihl, ip_tos, ip_len,
                                ip_id, ip_flags_off,
                                ip_ttl, ip_proto,
                                ip_chk, ip_src, ip_dst)
        ip_checksum = self._compute_ip_checksum(ip_header)
        # Insert checksum into IP header
        ip_header = ip_header[:10] + struct.pack('!H', ip_checksum) + ip_header[12:]
        # Construct TCP header for response
        tcp_src_port = dst_port  # swap
        tcp_dst_port = src_port
        tcp_seq_num = resp_seq
        tcp_ack_num = resp_ack
        offset_res_flags = (5 << 12) | resp_flags
        tcp_win = self.win
        tcp_chk = 0
        tcp_urg_ptr = 0
        tcp_header = struct.pack('!HHLLHHHH',
                                 tcp_src_port, tcp_dst_port,
                                 tcp_seq_num, tcp_ack_num,
                                 offset_res_flags, tcp_win,
                                 tcp_chk, tcp_urg_ptr)
        tcp_checksum = self._compute_tcp_checksum(ip_src, ip_dst, tcp_header, b"")
        tcp_header = tcp_header[:16] + struct.pack('!H', tcp_checksum) + tcp_header[18:]
        # Final packet
        response_packet = ip_header + tcp_header
        try:
            self.tcp_conn.send(response_packet)
            logger.debug("Sent deceptive packet on %s: %s:%d <- %s:%d [RST flags=0x%x, TTL=%d, WIN=%d]",
                         settings.NIC_PROBE, src_ip, src_port, dst_ip, dst_port, resp_flags, self.ttl, self.win)
        except Exception as e:
            logger.error("Failed to send deceptive packet on %s: %s", settings.NIC_PROBE, e)
        return True
