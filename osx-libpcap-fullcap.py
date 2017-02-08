#!/usr/bin/python
# Pure Python Tiny Packet Snifer
# Author: Alexander Rymdeko-Harvey
# Twitter: @Killswitch-GUI

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

import ctypes
import threading
import sys
import os
import errno
import base64

DEBUG = False
IN_MEMORY = False
PCAP_FILENAME = 'test.pcap'
OSX_PCAP_DYLIB = '/usr/lib/libpcap.A.dylib'
OSX_LIBC_DYLIB = '/usr/lib/libSystem.B.dylib'
PCAP_ERRBUF_SIZE = 256
PCAP_CAPTURE_COUNT = 1000
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
    cp = pkthdr.contents.caplen
    if DEBUG:
        print "packet capture length: " + str(pkthdr.contents.caplen)
        print "packet tottal length: " + str(pkthdr.contents.len)
        print(pkthdr.contents.tv_sec,pkthdr.contents.caplen,pkthdr.contents.len)
        print packet.contents[:cp]

if DEBUG:
    print "-------------------------------------------"
libc = ctypes.CDLL(OSX_LIBC_DYLIB, use_errno=True)
if not libc:
    if DEBUG:
        print "Error loading C libary: %s" % errno.errorcode[ctypes.get_errno()]
if DEBUG:
    print "* C runtime libary loaded: %s" % OSX_LIBC_DYLIB
pcap = ctypes.CDLL(OSX_PCAP_DYLIB, use_errno=True)
if not pcap:
    if DEBUG:
        print "Error loading C libary: %s" % errno.errorcode[ctypes.get_errno()]
if DEBUG:
    print "* C runtime libary loaded: %s" % OSX_PCAP_DYLIB
    print "* C runtime handle at: %s" % pcap
    print "-------------------------------------------"
pcap_lookupdev = pcap.pcap_lookupdev
pcap_lookupdev.restype = ctypes.c_char_p
dev = pcap.pcap_lookupdev()
if DEBUG:
    print "* Device handle at: %s" % dev

net = ctypes.c_uint()
mask = ctypes.c_uint()
pcap.pcap_lookupnet(dev,ctypes.byref(net),ctypes.byref(mask),err_buf)
if DEBUG:
    print "* Device IP to bind: %s" % net
    print "* Device net mask: %s" % mask

#pcap_t *pcap_open_live(const char *device, int snaplen,int promisc, int to_ms, char *errbuf)
pcap_open_live = pcap.pcap_open_live
pcap_open_live.restype = ctypes.POINTER(ctypes.c_void_p)
pcap_create = pcap.pcap_create
pcap_create.restype = ctypes.c_void_p
#pcap_handle = pcap.pcap_create(dev, err_buf)
pcap_handle = pcap.pcap_open_live(dev, 1024, packet_count_limit, timeout_limit, err_buf)
if DEBUG:
    print "* Live capture device handle at: %s" % pcap_handle 

pcap_can_set_rfmon = pcap.pcap_can_set_rfmon
pcap_can_set_rfmon.argtypes = [ctypes.c_void_p]
if (pcap_can_set_rfmon(pcap_handle) == 1):
    if DEBUG:
        print "* Can set interface in monitor mode"

pcap_pkthdr_p = ctypes.POINTER(pcap_pkthdr)()
packetdata = ctypes.POINTER(ctypes.c_ubyte*65536)()
#print pcap.pcap_next(pcap_handle,ctypes.byref(pcap_pkthdr_p))
if DEBUG:
    print "-------------------------------------------"
pcap_dump_open = pcap.pcap_dump_open
pcap_dump_open.restype = ctypes.POINTER(ctypes.c_void_p)
pcap_dumper_t = pcap.pcap_dump_open(pcap_handle,PCAP_FILENAME)
if DEBUG:
    print "* Pcap dump handle created: %s" % pcap_dumper_t 
    print "* Pcap data dump to file: %s" % (PCAP_FILENAME) 
    print "* Max Packets to capture: %s" % (PCAP_CAPTURE_COUNT)
    print "-------------------------------------------"

# CMPFUNC = ctypes.CFUNCTYPE(ctypes.c_void_p, ctypes.c_void_p)
# def pkthandler_callback(pcap_pkthdr,pdata):
#     pcap.pcap_dump(pcap_dumper_t,pcap_pkthdr,pdata)
# cmp_func = CMPFUNC(pkthandler_callback)
# pcap.pcap_loop(pcap_handle, PCAP_CAPTURE_COUNT, cmp_func, 0)

c = 0
while True:
    if (pcap.pcap_next_ex(pcap_handle, ctypes.byref(pcap_pkthdr_p), ctypes.byref(packetdata)) == 1):
        pcap.pcap_dump(pcap_dumper_t,pcap_pkthdr_p,packetdata)
        #pkthandler(pcap_pkthdr_p,packetdata)
        c += 1
    if c > PCAP_CAPTURE_COUNT:
        if DEBUG:
            print "* Max packet count reached!"
        break
if DEBUG:
    print "-------------------------------------------"
    print "* Pcap dump handle now freeing"
pcap.pcap_dump_close(pcap_dumper_t)
if DEBUG:
    print "* Device handle now closing"
if not (pcap.pcap_close(pcap_handle)):
    if DEBUG:
        print "* Device handle failed to close!"
if not IN_MEMORY:
    f = open(PCAP_FILENAME, 'rb')
    data = base64.b64encode(f.read())
    f.close()
    os.system('rm -f %s' % PCAP_FILENAME)
    sys.stdout.write(data)
