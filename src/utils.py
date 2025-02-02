import struct
import random
import socket
import array


def calculate_checksum(data):
    """
    Computes checksum for a given data packet (IP, TCP, UDP).
    Ensures correct padding for odd-length data.
    """
    if len(data) % 2 != 0:
        data += b'\0'  # Padding for odd length

    res = sum(array.array("H", data))
    res = (res >> 16) + (res & 0xffff)
    res += res >> 16

    return (~res) & 0xffff


def generate_random_mac():
    """
    Generates a random MAC address.
    """
    return ':'.join(f'{random.randint(0, 255):02x}' for _ in range(6))


def generate_random_ip():
    """
    Generates a random private IP address.
    """
    return f"192.168.{random.randint(1, 255)}.{random.randint(1, 255)}"


def convert_mac_to_bytes(mac_str):
    """
    Converts a MAC address from string format to bytes.
    Example: "00:1A:2B:3C:4D:5E" -> b'\x00\x1A\x2B\x3C\x4D\x5E'
    """
    return struct.pack('!6B', *[int(x, 16) for x in mac_str.split(':')])


def convert_ip_to_bytes(ip_str):
    """
    Converts an IPv4 address from string to bytes.
    Example: "192.168.1.1" -> b'\xC0\xA8\x01\x01'
    """
    return socket.inet_aton(ip_str)


def convert_bytes_to_ip(ip_bytes):
    """
    Converts an IP address from bytes to string format.
    Example: b'\xC0\xA8\x01\x01' -> "192.168.1.1"
    """
    return socket.inet_ntoa(ip_bytes)


def convert_bytes_to_mac(mac_bytes):
    """
    Converts a MAC address from bytes to human-readable format.
    Example: b'\x00\x1A\x2B\x3C\x4D\x5E' -> "00:1A:2B:3C:4D:5E"
    """
    return ':'.join(f'{b:02x}' for b in mac_bytes)
