# import array

# def calculate_checksum(data):
    """
    Computes checksum for a given data packet (IP or TCP).
    """
#     if len(data) % 2 != 0:
#         data += b'\0'

#     res = sum(array.array("H", data))
#     res = (res >> 16) + (res & 0xffff)
#     res += res >> 16

#     return (~res) & 0xffff
