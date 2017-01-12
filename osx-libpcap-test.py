import ctypes
import threading
import sys
import os
import errno


# BSD 3-Clause License

# Copyright (c) 2017, Alexander Rymdeko-Harvey
# All rights reserved.

# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:

# * Redistributions of source code must retain the above copyright notice, this
#   list of conditions and the following disclaimer.

# * Redistributions in binary form must reproduce the above copyright notice,
#   this list of conditions and the following disclaimer in the documentation
#   and/or other materials provided with the distribution.

# * Neither the name of the copyright holder nor the names of its
#   contributors may be used to endorse or promote products derived from
#   this software without specific prior written permission.

# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.


OSX_PCAP_DYLIB = '/usr/lib/libpcap.A.dylib'
OSX_LIBC_DYLIB = '/usr/lib/libSystem.B.dylib'
PCAP_ERRBUF_SIZE = 256
packet_count_limit = ctypes.c_int(1)
timeout_limit = ctypes.c_int(1000) # In milliseconds 
err_buf = ctypes.create_string_buffer(PCAP_ERRBUF_SIZE)

class bpf_program(ctypes.Structure):
    _fields_ = [("bf_len", ctypes.c_int),("bf_insns", ctypes.c_void_p)]

class pcap_pkthdr(ctypes.Structure):
    _fields_ = [("tv_sec", ctypes.c_long), ("tv_usec", ctypes.c_long), ("caplen", ctypes.c_uint), ("len", ctypes.c_uint)]

class pcap_stat(ctypes.Structure):
    _fields_ = [("ps_recv",ctypes.c_uint), ("ps_drop",ctypes.c_uint), ("ps_ifdrop", ctypes.c_int)]

def pkthandler(pkthdr,packet):
    print("In callback:")
    print("pkthdr[0:7]:",pkthdr.contents.len)
    print(pkthdr.contents.tv_sec,pkthdr.contents.caplen,pkthdr.contents.len)
    print(packet.contents[:10])
    print()

print "-------------------------------------------"
libc = ctypes.CDLL(OSX_LIBC_DYLIB, use_errno=True)
if not libc:
    print "Error loading C libary: %s" % errno.errorcode[ctypes.get_errno()]
print "* C runtime libary loaded: %s" % OSX_LIBC_DYLIB
pcap = ctypes.CDLL(OSX_PCAP_DYLIB, use_errno=True)
if not pcap:
    print "Error loading C libary: %s" % errno.errorcode[ctypes.get_errno()]
print "* C runtime libary loaded: %s" % OSX_PCAP_DYLIB
print "* C runtime handle at: %s" % pcap

print "-------------------------------------------"
pcap_lookupdev = pcap.pcap_lookupdev
pcap_lookupdev.restype = ctypes.c_char_p
dev = pcap.pcap_lookupdev()
print "* Device handle at: %s" % dev

net = ctypes.c_uint()
mask = ctypes.c_uint()
pcap.pcap_lookupnet(dev,ctypes.byref(net),ctypes.byref(mask),err_buf)
print "* Device IP to bind: %s" % net
print "* Device net mask: %s" % mask

#pcap_t *pcap_open_live(const char *device, int snaplen,int promisc, int to_ms, char *errbuf)
pcap_open_live = pcap.pcap_open_live
pcap_open_live.restype = ctypes.POINTER(ctypes.c_void_p)
pcap_create = pcap.pcap_create
pcap_create.restype = ctypes.c_void_p
#pcap_handle = pcap.pcap_create(dev, err_buf)
pcap_handle = pcap.pcap_open_live(dev, 1024, packet_count_limit, timeout_limit, err_buf)
print "* Live capture device handle at: %s" % pcap_handle 

pcap_can_set_rfmon = pcap.pcap_can_set_rfmon
pcap_can_set_rfmon.argtypes = [ctypes.c_void_p]
if (pcap_can_set_rfmon(pcap_handle) == 1):
    print "* Can set interface in monitor mode"

pcap_pkthdr_p = ctypes.POINTER(pcap_pkthdr)()
packetdata = ctypes.POINTER(ctypes.c_ubyte*65536)()
#print pcap.pcap_next(pcap_handle,ctypes.byref(pcap_pkthdr_p))

if (pcap.pcap_next_ex(pcap_handle, ctypes.byref(pcap_pkthdr_p), ctypes.byref(packetdata)) == 1):
    print "* Packet captured!"
    pkthandler(pcap_pkthdr_p,packetdata)
