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
from lib import int_into_bytes

##
# Error Handling
from errors import GenericException
class Packet_Header_Error(GenericException):
    """ Errors relating to Packet Header problems.
    """
    pass

##
# Global Variables
DEBUG = False
HEADER_LENGTH_PACKET = 16

class Packet_Header(object):
    """ Abstracts the handling of a LibPCAP packet header for easier manipulation. The header
    structure can be found at https://wiki.wireshark.org/Development/LibpcapFileFormat and is as
    follows:

        +--------+---+---+---+---+---+---+---+---+
        | Offset | 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 |
        | Octet  |                               |
        +========+===+===+===+===+===+===+===+===+
        | 0      | ts_sec        | ts_usec       |
        +--------+---+---+---+---+---+---+---+---+
        | 8      | incl_len      | orig_len      |
        +--------+---+---+---+---+---+---+---+---+

    :ivar int ts_sec:
        The date and time when this packet was captured. This value is in seconds since
        ``January 1, 1970 00:00:00 GMT``; this is also known as a UN*X time_t. If this timestamp
        isn't based on GMT (UTC), use thiszone from the global header for adjustments.

    :ivar int ts_usec:
        In regular pcap files, the microseconds when this packet was captured, as an offset to
        ``ts_sec``.
        In nanosecond-resolution files, this is, instead, the nanoseconds when the packet was
        captured, as an offset to ``ts_sec``.
        .. Warning::
            This value shouldn't reach 1 second (in regular pcap files ``1 000 000``; in
            nanosecond-resolution files, ``1 000 000 000``); in this case ``ts_sec`` must be
            increased instead!

    :ivar int incl_len:
        The number of bytes of packet data actually captured and saved in the file. This value
        should never become larger than ``orig_len`` or the ``snaplen`` value of the global header.

    :ivar int orig_len:
        The length of the packet as it appeared on the network when it was captured. If ``incl_len``
        and ``orig_len`` differ, the actually saved packet size was limited by ``snaplen``.

    :ivar str bytes:
        A **binary** string containing the Packet Header as defined above starting at position 0.
        There may be additional bytes after (typically the packet as defined by the header) but that
        is not required. MUST be at least 16 bytes.
    """
    length = HEADER_LENGTH_PACKET


    @classmethod
    def parse_Packet_Header(cls, pcap_header, bytes):
        obj = cls(pcap_header, bytes)
        return (obj, bytes[HEADER_LENGTH_PACKET:],)


    def __init__(self, pcap_header, bytes):
        # Ensure the header is long enough to process
        if len(bytes) < HEADER_LENGTH_PACKET:
            raise Packet_Header_Error("Expected at least " + str(HEADER_LENGTH_PACKET) + " bytes." +
                                      " Received " + str(len(bytes)) + " bytes",
                                      [binascii.hexlify(bytes)])
        self.flip_bytes = pcap_header.flip_bytes
        ##
        # Parse Bytes
        self.bytes    = bytes[:HEADER_LENGTH_PACKET]
        self.ts_sec   = pcap_header.flip_bytes(bytes[0:4])
        self.ts_usec  = pcap_header.flip_bytes(bytes[4:8])
        self.incl_len = pcap_header.flip_bytes(bytes[8:12])
        self.orig_len = pcap_header.flip_bytes(bytes[12:16])
        # Sanity Check Lengths
        if self.incl_len > self.orig_len:
            raise Packet_Header_Error("Packet length cannot be greater than the original length")
        if self.incl_len > pcap_header.snaplen:
            raise Packet_Header_Error("Packet length cannot be greater than snaplen")
        # If in Debug Mode - Print this object
        if DEBUG:
            print str(self.__class__)
            for byte in self.bytes[:HEADER_LENGTH_PACKET]:
                sys.stdout.write(binascii.hexlify(byte) + " ")
            print ""
            for key, value in collections.OrderedDict(self).iteritems():
                print str(key) + " " + str(value)
            print ""


    def __iter__(self):
        me = collections.OrderedDict()
        me["raw_bytes"] = binascii.hexlify(self.bytes[:HEADER_LENGTH_PACKET])
        me["ts_sec   "] = binascii.hexlify(self.ts_sec)
        me["ts_usec  "] = binascii.hexlify(self.ts_usec)
        me["incl_len "] = binascii.hexlify(self.incl_len)
        me["orig_len "] = binascii.hexlify(self.orig_len)
        return me.iteritems()


    def decapsulate(self, new_length):
        """
        :type  new_length: int
        :param new_length: The new packet length, which will be written to ``incl_len`` and
            ``origin_len`` byte locations.
        """
        return (self.flip_bytes(self.ts_sec) +
                self.flip_bytes(self.ts_usec) +
                self.flip_bytes(int_into_bytes(new_length, 4))+
                self.flip_bytes(int_into_bytes(new_length, 4)))


    @property
    def packet_raw_bytes(self):
        """ Returns the "remaining" bytes, after the packet header.
        """
        return self.bytes[HEADER_LENGTH_PACKET:int(binascii.hexlify(self.incl_len, 16))]
