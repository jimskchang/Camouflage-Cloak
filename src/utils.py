import struct
import random
import socket
import array
import logging

# Set up logging
logging.basicConfig(
    format="%(asctime)s [%(levelname)s]: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    level=logging.INFO
)

def calculate_checksum(data):
    """
    Computes checksum for a given data packet (IP, TCP, UDP).
    Ensures correct padding for odd-length data.
    """
    if not isinstance(data, (bytes, bytearray)):
        logging.error("Invalid input: data must be bytes or bytearray.")
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
    if not is_valid_mac(mac_str):
        logging.error(f"Invalid MAC address format: {mac_str}")
        raise ValueError("Invalid MAC address format")

    return struct.pack('!6B', *[int(x, 16) for x in mac_str.split(":")])


def convert_ip_to_bytes(ip_str):
    """
    Converts an IPv4 address from string to bytes.
    Example: "192.168.1.1" -> b'\xC0\xA8\x01\x01'
    """
    if not is_valid_ip(ip_str):
        logging.error(f"Invalid IP address format: {ip_str}")
        raise ValueError("Invalid IP address format")

    return socket.inet_aton(ip_str)


def convert_bytes_to_ip(ip_bytes):
    """
    Converts an IP address from bytes to string format.
    Example: b'\xC0\xA8\x01\x01' -> "192.168.1.1"
    """
    if not isinstance(ip_bytes, bytes) or len(ip_bytes) != 4:
        logging.error("Invalid input: IP bytes must be exactly 4 bytes long.")
        raise ValueError("IP bytes must be exactly 4 bytes long")

    return socket.inet_ntoa(ip_bytes)


def convert_bytes_to_mac(mac_bytes):
    """
    Converts a MAC address from bytes to human-readable format.
    Example: b'\x00\x1A\x2B\x3C\x4D\x5E' -> "00:1A:2B:3C:4D:5E"
    """
    if not isinstance(mac_bytes, bytes) or len(mac_bytes) != 6:
        logging.error("Invalid input: MAC bytes must be exactly 6 bytes long.")
        raise ValueError("MAC bytes must be exactly 6 bytes long")

    return ':'.join(f'{b:02x}'.upper() for b in mac_bytes)


def convert_bytes_to_int(byte_data):
    """
    Converts a byte sequence to an integer.
    Example: b'\x00\x01' -> 1
    """
    return int.from_bytes(byte_data, byteorder='big')


def convert_int_to_bytes(value, length):
    """
    Converts an integer to a byte sequence of specified length.
    Example: 1 -> b'\x00\x01' (for length=2)
    """
    return value.to_bytes(length, byteorder='big')


def is_valid_mac(mac_str):
    """
    Validates a MAC address.
    Example: "00:1A:2B:3C:4D:5E" -> True
    """
    if not isinstance(mac_str, str):
        return False

    parts = mac_str.split(":")
    if len(parts) != 6:
        return False

    try:
        return all(0 <= int(x, 16) <= 255 for x in parts)
    except ValueError:
        return False


def is_valid_ip(ip_str):
    """
    Validates an IPv4 address.
    Example: "192.168.1.1" -> True
    """
    try:
        socket.inet_aton(ip_str)
        return True
    except socket.error:
        return False
