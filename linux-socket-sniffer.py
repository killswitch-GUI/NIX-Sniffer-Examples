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

import socket, time
from datetime import datetime
import struct

def outputPcapPFile(fileName):
  # magic_number="\xC3\xD4\xA1\xB2", 
  # version_major="\x00\x02" 
  # version_minor="\x00\x04"
  # thiszone="\x00\x00\x00\x00"
  # sigfigs="\x00\x00\x00\x00"
  # snaplen="\x00\x00\x00\x04"
  # network="\x00\x01\x00\x00"
  pcapHeader = struct.pack("@IHHIIII",0xa1b2c3d4,2,4,0,0,0x040000,1)
  with open(str(fileName), 'wb+') as f:
    f.write(pcapHeader)


def ouputPcapPacket(fileName, pLen, packet):
  # "ts_sec", "\x00\x00\x00\x00"
  # "ts_usec", "\x00\x00\x00\x00"
  # "incl_len", "\x00\x00\x00\x00"
  # "orig_len", "\x00\x00\x00\x00"
  t0, t1, t2, t3, t4, t5, t6, t7, t8 = time.gmtime()
  tstamp = time.mktime((t0, t1, t2, t3, t4, t5, 0, 0, 0))
  dt = datetime.now()
  mstamp = dt.microsecond
  pcapPacket = struct.pack("@IIII",tstamp,mstamp,pLen,pLen)
  with open(str(fileName), 'ab+') as f:
    f.write(pcapPacket)
    f.write(packet)


def parseEthernetHeader(data):
    dst = struct.unpack('!BBBBBB',data[:6])        # destination host address
    src = struct.unpack('!BBBBBB',data[6:12])      # source host address
    nextType = struct.unpack('!H',data[12:14])[0]  # IP? ARP? RARP? etc
    return dst, src, nextType

def parseIpHeader(data):
    ihl = struct.unpack('!B',data[14:15])[0]          # 4 bit version 4 bit ihl
    tos = struct.unpack('!B',data[15:16])[0]          # Type of service
    totalLen = struct.unpack('!H',data[16:18])[0]     # IP header length
    ident = struct.unpack('!H',data[18:20])[0]        # IP ident
    fragFlags = struct.unpack('!H',data[20:22])[0]    # Frag_and_flags
    ttl = struct.unpack('!B',data[22:23])[0]          # Packet Time-to-Live
    proto = struct.unpack('!B',data[23:24])[0]        # Next protocol
    checksum = struct.unpack('!H',data[24:26])[0]     # checksum
    sourceIp = struct.unpack('!I',data[26:30])[0]     # Source IP addr
    destIp = struct.unpack('!I',data[30:34])[0]       # Dest IP addr

    sourceIpStr = parseIpAddr(data[26:30])            # hton ip
    destIpStr = parseIpAddr(data[30:34])              # hton ip
    return proto, sourceIpStr, destIpStr

def parseTcpHeader(data):
  sourcePort = struct.unpack('!H',data[34:36])[0]       # source port (set pointer to end of IP Header)
  destPort = struct.unpack('!H',data[36:38])[0]         # destination port
  sequence = struct.unpack('!I',data[38:42])[0]         # sequence number - 32 bits
  acknowledge = struct.unpack('!I',data[42:46])[0]      # acknowledgement number - 32 bits
  return sourcePort, destPort

def parseUdpHeader(data):
  sourcePort = struct.unpack('!H',data[34:36])[0]       # source port (set pointer to end of IP Header)
  destPort = struct.unpack('!H',data[36:38])[0]         # destination port
  udpLength = struct.unpack('!H',data[38:40])[0]        # Udp packet length
  udpChecksum = struct.unpack('!H',data[40:42])[0]      # Udp checksum (optional)
  return sourcePort, destPort

def parseIcmpHeader(data):
  typeCode = struct.unpack('!H',data[34:36])[0]       # ICMP Error type
  code = struct.unpack('!H',data[36:38])[0]           # Type sub code
  checksum = struct.unpack('!H',data[38:40])[0]       # checksum
  idCode = struct.unpack('!H',data[40:42])[0]         # ICMP ID code
  seq = struct.unpack('!H',data[42:44])[0]            # Seq number

def parseIpAddr(data):
  # build dec dot notation IP sting from bytes
  ipOct = []
  ipOct.append(str(struct.unpack('!B', data[0:1])[0]))  # octet 1
  ipOct.append(str(struct.unpack('!B', data[1:2])[0]))  # octet 2  
  ipOct.append(str(struct.unpack('!B', data[2:3])[0]))  # octet 3
  ipOct.append(str(struct.unpack('!B', data[3:4])[0]))  # octet 4
  ipStr = '.'.join(ipOct)
  return ipStr

def socketSniffer(fileName,ipFilter,portFilter,maxSize, maxPackets):
  try:
      s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW ,socket.ntohs(0x0003))
      print '[*] Socket successfully created'
  except socket.error , msg:
      print '[!] Socket could not be created. Error Code : ' + str(msg[0]) + ' Message ' + msg[1]
      return
  # build pcap file header and output
  outputPcapPFile(fileName)
  packetCounter = 0
  sizeCounter = 0
  maxSize = maxSize * 1024 * 1024
  while (packetCounter < maxPackets):
      if (sizeCounter > maxSize):
        break
      packet = s.recvfrom(65565)
      pLen = len(packet[0])
      if (ipFilter or portFilter):
        packetOut = False
        dst, src, nextType = parseEthernetHeader(packet[0])
        if (hex(nextType) == hex(0x800)):
          # evaluate the IP packet
          proto, sourceIpStr, destIpStr = parseIpHeader(packet[0])
          # ICMP (1)
          # TCP  (6)
          # UDP  (17)
          if (proto == 6):
            sourcePort, destPort = parseTcpHeader(packet[0])
            print sourcePort
            if ipFilter and portFilter:
              if (ipFilter == sourceIpStr or ipFilter == destIpStr) and (portFilter == sourcePort or portFilter == destPort):
                packetOut = True
            elif (ipFilter == sourceIpStr or ipFilter == destIpStr):
              packetOut = True
            elif (portFilter == sourcePort or portFilter == destPort):
              packetOut = True
          elif (proto == 17):
            sourcePort, destPort = parseUdpHeader(packet[0])
            if ipFilter and portFilter:
              if (ipFilter == sourceIpStr or ipFilter == destIpStr) and (portFilter == sourcePort or portFilter == destPort):
                packetOut = True
            elif (ipFilter == sourceIpStr or ipFilter == destIpStr):
              packetOut = True
            elif (portFilter == sourcePort or portFilter == destPort):
              packetOut = True
          else:
            if (ipFilter == sourceIpStr or ipFilter == destIpStr):
              packetOut = True
        if packetOut:
          ouputPcapPacket(fileName ,pLen, packet[0])
          # counters
          sizeCounter += pLen
          packetCounter += 1
      else: 
        ouputPcapPacket(fileName ,pLen, packet[0])
        # counters
        sizeCounter += pLen
        packetCounter += 1

  printStr =  "[*] PCAP Complete"
  printStr += "\n  - Total packet count: " + str(packetCounter)
  printStr += "\n  - PCAP size in MB: " + str((float(sizeCounter) / 1024) / 1024)
  printStr += "\n  - PCAP filename: " + str(fileName)
  print printStr

fileName2 = 'test.pcap'
ipFilter = 0
portFilter = 443
maxSize = 100
maxPackets = 1000
socketSniffer(fileName2,ipFilter,portFilter,maxSize,maxPackets)
