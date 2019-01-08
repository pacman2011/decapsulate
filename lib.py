"""
:codeauthor: Shane Boissevain <sboissevain@nsslabs.com>
:date: 2019-01-05

Houses the "helper" functions used throughout this program.
"""

##
# Python Imports
import sys
import binascii
import collections
import struct
import binascii


def bytes_to_int(bytes):
    """ Converts the given ``binary string`` to a decimal integer.
    """
    return int(binascii.hexlify(bytes), 16)


def int_into_bytes(integer, num_bytes):
    """ Converts the given ``integer`` to a **binary** string, containing ``num_bytes``, in the
    correct order.

    .. example::

        ``` python
        int_to_bytes(2, 85)
        >>> "\x00\x55"
        ```

    :rtype:   binary string
    :returns: The given integer as binary data.
    """
    # int_to_bytes(85, 2) --> "0055"
    hex_str  = ("{:0" + str(num_bytes*2) + "x}").format(integer)
    # ["00", "55"]
    hex_str_by_byte = map(''.join, zip(*[iter(hex_str)]*2))
    if len(hex_str_by_byte) > num_bytes:
        raise Exception("'" + str(integer) + " does not fit into " + str(num_bytes) + " bytes.")
    # Write the binary data to return value
    bytes = ""
    for byte_string in hex_str_by_byte:
        bytes += struct.pack("B", int(byte_string, 16))
    return bytes
