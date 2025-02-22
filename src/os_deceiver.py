
            with open(file_path, "r") as f:
                self.packet_data[proto] = f.read().splitlines()

        logging.info(f"Loaded OS fingerprint data from {self.os_record_path}")

    def _parse_ethernet_ip(self, packet):
        """
        Parses Ethernet and IP headers.
        """
        try:
            eth_header = packet[:settings.ETH_HEADER_LEN]
            eth = struct.unpack("!6s6sH", eth_header)
            eth_protocol = socket.ntohs(eth[2])

            ip_header = packet[settings.ETH_HEADER_LEN: settings.ETH_HEADER_LEN + settings.IP_HEADER_LEN]
            _, _, _, _, _, _, PROTOCOL, _, src_IP, dest_IP = struct.unpack("!BBHHHBBH4s4s", ip_header)

            return eth_protocol, src_IP, dest_IP, PROTOCOL
        except struct.error as e:
            logging.error(f"Error parsing Ethernet/IP headers: {e}")
            return None, None, None, None

    def os_record(self, max_packets=100):
        """
        Captures OS fingerprinting packets (ARP, ICMP, TCP, UDP) and logs them.
        """
        logging.info(f"Capturing packets on {settings.NIC} for {self.target_host_str} (Max: {max_packets}, Timeout: 2 min)")
        
        packet_files = {
            "arp": os.path.join(self.os_record_path, "arp_record.txt"),
            "icmp": os.path.join(self.os_record_path, "icmp_record.txt"),
            "tcp": os.path.join(self.os_record_path, "tcp_record.txt"),
            "udp": os.path.join(self.os_record_path, "udp_record.txt")
        }

        start_time = time.time()
        packet_count = 0

        try:
            while packet_count < max_packets:
                if time.time() - start_time > 120:
                    logging.info("Timeout reached. Exiting OS fingerprinting mode.")
                    break

                packet, addr = self.conn.sock.recvfrom(65565)
                logging.debug(f"Packet received from {addr}")

                eth_protocol, src_IP, dest_IP, PROTOCOL = self._parse_ethernet_ip(packet)

                if dest_IP != self.target_host:
                    continue

                proto_type = None
                if PROTOCOL == 1:
                    proto_type = "icmp"
                elif PROTOCOL == 6:
                    proto_type = "tcp"
                elif PROTOCOL == 17:
                    proto_type = "udp"
                elif eth_protocol == 1544:
                    proto_type = "arp"

                if proto_type:
                    with open(packet_files[proto_type], "a") as f:
                        f.write(str(packet) + "\n")

                    packet_count += 1
                    logging.info(f"Captured {proto_type.upper()} Packet ({packet_count})")

            if packet_count == 0:
                logging.warning("No packets captured! Check network interface settings and traffic.")

            logging.info(f"OS Fingerprinting Completed. Captured {packet_count} packets.")

        except KeyboardInterrupt:
            logging.info("User interrupted capture. Exiting...")
        except Exception as e:
            logging.error(f"Error while capturing packets: {e}")

        logging.info("Returning to command mode.")
