"""
:author: Shane Boissevain
:date:   2019-01-05
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
class Ethernet_Error(GenericException):
    """ Errors relating to Ethernet Frame problems.
    """
    pass

##
# Global Variables
DEBUG = False
FRAME_LENGTH_ETHERNET = 14

class Ethernet_Frame(object):
    """ Abstracts the handling of a LibPCAP's Ethernet Frame for easier manipulation.

    :ivar str dst_mac:
        A **binary string** containing the MAC address of the receiving machine.

    :ivar str src_mac:
        A **binary string** containing the MAC address of the sending machine.

    :ivar str type:
        A **binary string** containing the type of packet.
    """
    length = FRAME_LENGTH_ETHERNET


    @classmethod
    def parse_Ethernet_Frame(cls, bytes):
        obj = cls(bytes)
        return (obj, bytes[FRAME_LENGTH_ETHERNET:],)


    def __init__(self, bytes):
        # Ensure the Frame is long enough to process
        if len(bytes) < FRAME_LENGTH_ETHERNET:
            raise Packet_Header_Error("Expected at least " + str(FRAME_LENGTH_ETHERNET) + " bytes." +
                                    " Received " + len(bytes) + " bytes", [binascii.hexifly(bytes)])
        ##
        # Parse Bytes
        self.dst_mac = bytes[0:6]
        self.src_mac = bytes[6:12]
        self.type    = bytes[12:14]
        # Sanity Check type
        if binascii.hexlify(self.type) != "0800":
            raise Ethernet_Error("IPv4 Packets ONLY (type = 0x0800)", [dict(self)])
        # If in Debug Mode - Print this object
        if DEBUG:
            print str(self.__class__)
            for byte in bytes[:FRAME_LENGTH_ETHERNET]:
                sys.stdout.write(binascii.hexlify(byte) + " ")
            print ""
            for key, value in collections.OrderedDict(self).iteritems():
                print str(key) + " " + str(value)
            print ""


    def __iter__(self):
        me = collections.OrderedDict()
        me["bytes  "] = binascii.hexlify(self.raw_bytes)
        me["dst_mac"] = binascii.hexlify(self.dst_mac)
        me["src_mac"] = binascii.hexlify(self.src_mac)
        me["type   "] = binascii.hexlify(self.type)
        return me.iteritems()


    @property
    def raw_bytes(self):
        """ Returns the "raw bytes" **binary string** that comprise the Ethernet Frame.
        """
        return self.dst_mac + self.src_mac + self.type

