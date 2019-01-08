"""
:author: Shane Boissevain
:date:   2019-01-05
:ref:    https://wiki.wireshark.org/Development/LibpcapFileFormat
"""

##
# Python Imports
import sys
import binascii
import collections

##
# Project Imports

##
# Error Handling
from errors import GenericException
class PCAP_Header_Error(GenericException):
    """ Errors relating to PCAP_Header problems.
    """
    pass

##
# Global Variables
DEBUG = False
HEADER_LENGTH_PCAP  = 24
MAGIC_NUMBER        = "a1b2c3d4"    # Identical
MAGIC_SWAP          = "d4c3b2a1"    # Swapped
MAGIC_NANO          = "a1b23c4d"    # NanoSecond Resolution
MAGIC_SWAP_NANO     = "4d3cb2a1"    # NanoSecond Resolution AND swapped
VALID_MAGIC_NUMBERS = [MAGIC_NUMBER, MAGIC_SWAP, MAGIC_NANO, MAGIC_SWAP_NANO]


class PCAP_Header(object):
    """ Abstracts the PCAP header for easier manipulation. The Standard PCAP Lib Header is defined
    as the following per https://wiki.wireshark.org/Development/LibpcapFileFormat:

        +--------+---+---+---+---+-------+-------+-------+-------+
        | Offset | 0 | 1 | 2 | 3 | 4     | 5     | 6     | 7     |
        | Octet  |                                               |
        +========+===+===+===+===+=======+=======+=======+=======+
        | 0      | Magic Number  | Major Version | Minor Version |
        +--------+---+---+---+---+-------+-------+-------+-------+
        | 8      | This Zone     | sigfigs                       |
        +--------+---+---+---+---+-------+-------+-------+-------+
        | 16     | snaplen       | network                       |
        +--------+---+---+---+---+-------+-------+-------+-------+

    :ivar str magic_number:
        Used to detect the file format itself and the byte ordering. The writing application writes
        ``0xa1b2c3d4`` with it's native byte ordering format into this field. The reading
        application will read either ``0xa1b2c3d4`` (identical) or ``0xd4c3b2a1`` (swapped). If the
        reading application reads the swapped ``0xd4c3b2a1`` value, it knows that all the following
        fields will have to be swapped too.
        For nanosecond-resolution files, the writing application writes ``0xa1b23c4d``, with the two
        nibbles of the two lower-order bytes swapped, and the reading application will read either
        ``0xa1b23c4d`` (identical) or ``0x4d3cb2a1`` (swapped).

    :ivar int version_major:
        The **Major** version number of this file format.

    :ivar int version_minor:
        The **Minor** version number of this file format

    :ivar int thiszone:
        The correction time in seconds between GMT (UTC) and the local timezone of the following
        packet header timestamps.
        .. Example::
            If the timestamps are in GMT (UTC), thiszone is simply 0. If the timestamps are in
            Central European time (Amsterdam, Berlin, ...) which is GMT + 1:00, thiszone must be
            -3600. In practice, time stamps are always in GMT, so thiszone is always 0.

    :ivar int sigfigs:
        In theory, the accuracy of time stamps in the capture; in practice, all tools set it to 0.

    :ivar int snaplen:
        The "snapshot length" for the capture (typically ``65535`` or even more, but might be
        limited by the user).

    :ivar str network:
        The link-layer header type, specifying the type of headers at the beginning of the packet
        (e.g. 1 for Ethernet, see tcpdump.org's link-layer header types page for details); this can
        be various types such as 802.11, 802.11 with various radio information, PPP, Token Ring,
        FDDI, etc.

    :ivar str bytes:
        A **binary** string containing the PCAP Global Header as defined above starting at position
        0. There may be additional bytes after (typically the packet as defined by the header) but
        that is not required. MUST be at least 24 bytes.
    """
    length = HEADER_LENGTH_PCAP


    @classmethod
    def parse_PCAP_Header(cls, bytes):
        obj = cls(bytes)
        return (obj, bytes[HEADER_LENGTH_PCAP:],)


    def __init__(self, bytes):
        # Ensure the header is long enough to process
        if len(bytes) < HEADER_LENGTH_PCAP:
            raise PCAP_Header_Error("Expected at least " + str(HEADER_LENGTH_PCAP) + " bytes." +
                                    " Received " + len(bytes) + " bytes", [binascii.hexifly(bytes)])
        ##
        # Parse Bytes
        self.magic_number  = bytes[0:4]
        # Sanity Check Magic Number
        if binascii.hexlify(self.magic_number) not in VALID_MAGIC_NUMBERS:
            raise PCAP_Header_Error("Magic Number not recoganized. Is this is a PCAP file?",
                                    [self.magic_number])
        self.version_major = self.flip_bytes(bytes[4:6])
        self.version_minor = self.flip_bytes(bytes[6:8])
        self.thiszone      = self.flip_bytes(bytes[8:12])
        self.sigfigs       = self.flip_bytes(bytes[12:16])
        self.snaplen       = self.flip_bytes(bytes[16:20])
        self.network       = self.flip_bytes(bytes[20:24])
        # If in Debug Mode - Print this object
        if DEBUG:
            print str(self.__class__)
            for byte in bytes[:HEADER_LENGTH_PCAP]:
                sys.stdout.write(binascii.hexlify(byte) + " ")
            print ""
            for key, value in collections.OrderedDict(self).iteritems():
                print str(key) + " " + str(value)
            print ""


    def __iter__(self):
        me = collections.OrderedDict()
        me["raw_bytes    "] = binascii.hexlify(self.raw_bytes)
        me["magic_number "] = binascii.hexlify(self.magic_number)
        me["version_major"] = binascii.hexlify(self.version_major)
        me["version_minor"] = binascii.hexlify(self.version_minor)
        me["thiszone     "] = binascii.hexlify(self.thiszone)
        me["sigfigs      "] = binascii.hexlify(self.sigfigs)
        me["snaplen      "] = binascii.hexlify(self.snaplen)
        me["network      "] = binascii.hexlify(self.network)
        return me.iteritems()


    def flip_bytes(self, bytes):
        """ Flips the bytes from Little to Big Endian, if required.
        """
        byte_list = list(bytes)
        if binascii.hexlify(self.magic_number) in [MAGIC_SWAP, MAGIC_SWAP_NANO]:
            byte_list.reverse()
        return ''.join(byte_list)


    @property
    def raw_bytes(self):
        return (self.magic_number                   + self.flip_bytes(self.version_major) +
                self.flip_bytes(self.version_minor) + self.flip_bytes(self.thiszone     ) +
                self.flip_bytes(self.sigfigs      ) + self.flip_bytes(self.snaplen      ) +
                self.flip_bytes(self.network      ))







