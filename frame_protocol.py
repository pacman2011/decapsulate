"""
:author: Shane Boissevain
:date:   2019-01-07
"""

##
# Python Imports
import sys
import binascii
import collections

##
# Project Imports
from frame_internet import FRAME_LENGTH_INTERNET
##
# Error Handling
from errors import GenericException
class Protocol_Frame_Error(GenericException):
    """ Errors relating to Protocol Frame problems.
    """
    pass

##
# Global Variables
DEBUG = False

PROTO_ICMP        = 1
FRAME_LENGTH_ICMP = 8

PROTO_TCP         = 6
FRAME_LENGTH_TCP  = 1000

PROTO_UDP         = 17
FRAME_LENGTH_UDP  = 1000


class Protocol_Frame(object):
    """ Abstracts the handling of Protocol Frame for easier manipulation. Supported types are:
        * ``ICMP``
    Not yet implemented:
        * ``TCP``
        * ``UDP``
    """
    @classmethod
    def parse_Protocol_Frame(cls, internet_frame, bytes):
        obj = cls(internet_frame, bytes)
        return (obj, bytes[len(obj.raw_bytes):],)


    def __init__(self, internet_frame, bytes):
        # Ensure Supported Protocol
        if PROTO_ICMP == int(binascii.hexlify(internet_frame.protocol), 16):
            total_bytes  = int(binascii.hexlify(internet_frame.total_len), 16)
            self.header  = bytes[:FRAME_LENGTH_ICMP]
            self.payload = bytes[FRAME_LENGTH_ICMP:total_bytes - FRAME_LENGTH_INTERNET]
        else:
            raise Protocol_Frame_Error("Only ICMP is implemented")
        # If in Debug Mode - Print this object
        if DEBUG:
            print str(self.__class__)
            for byte in bytes[:total_bytes - FRAME_LENGTH_INTERNET]:
                sys.stdout.write(binascii.hexlify(byte) + " ")
            print ""
            for key, value in collections.OrderedDict(self).iteritems():
                print str(key) + " " + str(value)
            print ""


    def __iter__(self):
        me = collections.OrderedDict()
        me["bytes  "] = binascii.hexlify(self.raw_bytes)
        me["header "] = binascii.hexlify(self.header)
        me["payload"] = binascii.hexlify(self.payload)
        return me.iteritems()


    @property
    def raw_bytes(self):
        """ Returns the "raw bytes" **binary string** that comprises the Protocol Frame.
        """
        return self.header + self.payload
    @property
    def length(self):
        return len(self.header)
    @property
    def payload_length(self):
        return len(self.payload)
    @property
    def total_length(self):
        return self.length + self.payload_length
