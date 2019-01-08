"""
:author: Shane Boissevain
:date:   2019-01-05
"""

##
# Python Imports
import sys
import struct
import binascii
import collections

##
# Project Imports
from lib import int_into_bytes

##
# Error Handling
from errors import GenericException
class Internet_Frame_Error(GenericException):
    """ Errors relating to Internet Frame problems.
    """
    pass

##
# Global Variables
DEBUG = False
FRAME_LENGTH_INTERNET = 20


class Internet_Frame(object):
    """ Abstracts the handling of a LibPCAP's Internet Protocol Frame for easier manipulation.

    :ivar str ver_head_len:
        A **binary string** containing ***BOTH*** the IP Version and Header Length values.
        .. ToDo::
            Make this less lazy and actually split up the byte into two nibbles.

    :ivar str diff_serv:
        A **binary string** containing the Differentiated Services Field.

    :ivar str total_len:
        The length of the IP Packet.

    :ivar str ident:
        A **binary string** containing the packet's identification.

    :ivar str flags:
        A **binary string** containing the packet's IP flags.

    :ivar str ttl:
        The number of hops this packet can make.

    :ivar str protocol:
        The packet's protocol as a decimal number.

    :ivar str checksum:
        A **binary string** containing the packet's checksum

    :ivar str src_ip:
        A **binary string** containing the packet's source IP address.

    :ivar str dst_ip:
        A **binary string** containing the packet's destination IP address.
    """
    length = FRAME_LENGTH_INTERNET


    @classmethod
    def parse_Internet_Frame(cls, bytes):
        obj = cls(bytes)
        return (obj, bytes[FRAME_LENGTH_INTERNET:],)


    def __init__(self, bytes):
        if len(bytes) < FRAME_LENGTH_INTERNET:
            raise Internet_Frame_Error("Expected at least 20 bytes, received " + len(bytes) +
                                       " bytes.", [binascii.hexlify(bytes)])
        self.ver_head_len = bytes[0]
        if self.ver_head_len != binascii.unhexlify("45"):
            raise Internet_Frame_Error("IPv4 20-byte headers only (0x45)",
                                       [binascii.hexlify(bytes[0])])
        self.diff_serv   = bytes[1]
        self.total_len   = bytes[2:4]
        self.ident       = bytes[4:6]
        self.flags       = bytes[6:8]
        self.ttl         = bytes[8]
        self.protocol    = bytes[9]
        self.checksum    = bytes[10:12]
        self.src_ip      = bytes[12:16]
        self.dst_ip      = bytes[16:20]
        # If in Debug Mode - Print this object
        if DEBUG:
            print str(self.__class__)
            for byte in bytes[:FRAME_LENGTH_INTERNET]:
                sys.stdout.write(binascii.hexlify(byte) + " ")
            print ""
            for key, value in collections.OrderedDict(self).iteritems():
                print str(key) + " " + str(value)
            print ""


    def __iter__(self):
        me = collections.OrderedDict()
        me["bytes        "] = binascii.hexlify(self.raw_bytes)
        me["ver_head_len "] = binascii.hexlify(self.ver_head_len)
        me["diff_serv    "] = binascii.hexlify(self.diff_serv)
        me["total_len    "] = binascii.hexlify(self.total_len)
        me["ident        "] = binascii.hexlify(self.ident)
        me["flags        "] = binascii.hexlify(self.flags)
        me["ttl          "] = binascii.hexlify(self.ttl)
        me["protocol     "] = binascii.hexlify(self.protocol)
        me["checksum     "] = binascii.hexlify(self.checksum)
        me["src_ip       "] = binascii.hexlify(self.src_ip)
        me["dst_ip       "] = binascii.hexlify(self.dst_ip)
        return me.iteritems()


    @property
    def raw_bytes(self):
        """ Returns the "raw bytes" **binary string** that comprise the Ethernet Frame.
        """
        return (self.ver_head_len + self.diff_serv + self.total_len + self.ident  + self.flags +
                self.ttl          + self.protocol  + self.checksum  + self.src_ip + self.dst_ip)
