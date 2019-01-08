"""
:author: Shane Boissevain
:date:   2019-01-05
"""

##
# Python Imports
import binascii
import collections

##
# Project Imports
from header_packet  import Packet_Header
from frame_ethernet import Ethernet_Frame
from frame_internet import Internet_Frame
from frame_protocol import Protocol_Frame

##
# Error Handling
from errors import GenericException
class Packet_Error(GenericException):
    """ Errors relating to PCAP_Header problems.
    """
    pass

##
# Global Variables


class Packet(object):
    """ Abstracts the handling of a LibPCAP packet for easier manipulation.

    :type bytes: **Binary String**
    :ivar bytes: The original Raw_Bytes that apply to this packet.

    :type header: :class:`header_packet.Packet_Header`
    :ivar header: The packet header (defined in LibPCAP) that precedes this packet.

    :type ethernet: :class:`frame_ethernet.Ethernet_Frame`
    :ivar ethernet: The object that houses all attributes and bytes related to the Ethernet Frame.

    :type internet: :class:`frame_internet.Internet_Frame`
    :ivar internet: The object that houses all attributes and bytes related to the Internet Frame.

    :type protocol: :class:`frame_protocol.Protocol_Frame`
    :ivar protocol: The object that houses all attributes and bytes related to the Packet Frame.

    :type raw_bytes: **binary** string
    :ivar raw_bytes: The raw bytes on the wire
    """
    @classmethod
    def parse_Packet(cls, pcap_header, bytes):
        """ Parses a packet from ``bytes`` and returns the :class:`~packet.Packet` object, along
        with the remaining bytes after parsing.

        :rtype:   (:class:`~packet.Packet`, **binary string**)
        :returns: Tuple containing the parsed packet, and the remaining bytes.
        """
        obj = cls(pcap_header, bytes)
        return (obj, bytes[obj.packet_header.length + obj.length:],)


    def __init__(self, pcap_header, raw_bytes):
        # Build the frames out
        (self.packet_header, bytes) = Packet_Header.parse_Packet_Header(pcap_header, raw_bytes)
        (self.ethernet,      bytes) = Ethernet_Frame.parse_Ethernet_Frame(bytes)
        (self.internet,      bytes) = Internet_Frame.parse_Internet_Frame(bytes)
        (self.protocol,      bytes) = Protocol_Frame.parse_Protocol_Frame(self.internet, bytes)
        self.bytes                  = raw_bytes[:self.packet_header.length + self.length]


    def __str__(self):
        ret_str  = "Packet Header:  " + str(collections.OrderedDict(self.packet_header)) + "\n"
        ret_str += "Ethernet Frame: " + str(collections.OrderedDict(self.ethernet))      + "\n"
        ret_str += "Internet Frame: " + str(collections.OrderedDict(self.internet))      + "\n"
        ret_str += "Protocol Frame: " + str(collections.OrderedDict(self.protocol))      + "\n"
        return ret_str


    def decapsulate(self):
        """ Decapsulates the packet by removing the Internet and Protocol Frames, and shifting the
        Protocol's payload to the Internet Frame byte offset.

        :rtype:   **Binary** string
        :returns: The binary string for the decapsulated packet.
        """
        decap_bytes  = self.packet_header.decapsulate(self.decap_length)
        decap_bytes += self.ethernet.raw_bytes
        decap_bytes += self.protocol.payload
        return decap_bytes


    @property
    def length(self):
        return self.ethernet.length + int(binascii.hexlify(self.internet.total_len), 16)
    @property
    def total_length(self):
        return self.packet_header.length + self.length
    @property
    def decap_length(self):
        return len(self.ethernet.raw_bytes) + len(self.protocol.payload)












