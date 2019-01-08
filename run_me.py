#!/usr/bin/env python

##
# Fix Path
import __init__

##
# Python Imports
import os
import sys
import binascii

##
# Project Imports
from header_pcap    import PCAP_Header
from packet         import Packet
##
# Global Variables


if __name__ == "__main__":
    # Read the pcap file as binary data
    with open(sys.argv[1], "rb") as file:
        raw_bytes = file.read()
    # PCAP Header
    (pcap_header, raw_bytes)   = PCAP_Header.parse_PCAP_Header(raw_bytes)
    packets = []
    while len(raw_bytes) != 0:
        (packet, raw_bytes) = Packet.parse_Packet(pcap_header, raw_bytes)
        packets.append(packet)
    # Re-Write decapsulated packets
    decap_bytes = pcap_header.raw_bytes
    for packet in packets:
        decap_bytes += packet.decapsulate()
    filepath = os.path.join(os.path.dirname(sys.argv[1]), "decap_" + os.path.basename(sys.argv[1]))
    with open(filepath, "wb") as file:
        file.write(decap_bytes)
