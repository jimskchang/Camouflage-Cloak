import struct
import random
import socket
import array


def calculate_checksum(data):
    """
    Computes checksum for a given data packet (IP, TCP, UDP).
    Ensures correct padding for odd-length data.
    """
    if not isinstance(data, (bytes, bytearray)):
        raise ValueError("Input data must be bytes or bytearray")

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
    return ':'.join(f'{random.randint(0, 255):02x}' for _ in range(6)).upper()


def generate_random_ip(private_only=True):
    """
    Generates a random IP address.
    By default, it generates private IPs unless private_only=False.
    """
    if private_only:
        ranges = [
            (10, random.randint(0, 255), random.randint(0, 255), random.randint(1, 254)),  # 10.x.x.x
            (192, 168, random.randint(0, 255), random.randint(1, 254)),  # 192.168.x.x
            (172, random.randint(16, 31), random.randint(0, 255), random.randint(1, 254))  # 172.16.x.x - 172.31.x.x
        ]
        return ".".join(map(str, random.choice(ranges)))
    else:
        return ".".join(str(random.randint(1, 255)) for _ in range(4))


def convert_mac_to_bytes(mac_str):
    """
    Converts a MAC address from string format to bytes.
    Example: "00:1A:2B:3C:4D:5E" -> b'\x00\x1A\x2B\x3C\x4D\x5E'
    """
    try:
        return struct.pack('!6B', *[int(x, 16) for x in mac_str.split(':')])
    except ValueError:
        raise ValueError("Invalid MAC address format")


def convert_ip_to_bytes(ip_str):
    """
    Converts an IPv4 address from string to bytes.
    Example: "192.168.1.1" -> b'\xC0\xA8\x01\x01'
    """
    try:
        return socket.inet_aton(ip_str)
    except socket.error:
        raise ValueError("Invalid IP address format")


def convert_bytes_to_ip(ip_bytes):
    """
    Converts an IP address from bytes to string format.
    Example: b'\xC0\xA8\x01\x01' -> "192.168.1.1"
    """
    if not isinstance(ip_bytes, bytes) or len(ip_bytes) != 4:
        raise ValueError("Input must be a 4-byte string")
    return socket.inet_ntoa(ip_bytes)


def convert_bytes_to_mac(mac_bytes):
    """
    Converts a MAC address from bytes to human-readable format.
    Example: b'\x00\x1A\x2B\x3C\x4D\x5E' -> "00:1A:2B:3C:4D:5E"
    """
    if not isinstance(mac_bytes, bytes) or len(mac_bytes) != 6:
        raise ValueError("Input must be a 6-byte string")
    return ':'.join(f'{b:02x}'.upper() for b in mac_bytes)
