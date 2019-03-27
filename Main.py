#!/usr/bin/python

import pcapy
from struct import *


devs = pcapy.findalldevs()
inf=devs[0]

cap = pcapy.open_live(inf,65536,1,0)

count = 1
while count:
    (header,payload) = cap.next()
    l2hdr = payload[:14]
    lsdata=unpack("!6s6sH",l2hdr)

    srcmac="%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" %(ord(l2hdr[0]),ord(l2hdr[1]),ord(l2hdr[2]),ord(l2hdr[3]),ord(l2hdr[4]),ord(l2hdr[5]))
    dstmac = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (ord(l2hdr[6]), ord(l2hdr[7]), ord(l2hdr[8]), ord(l2hdr[9]), ord(l2hdr[10]), ord(l2hdr[11]))

    iphdr = unpack("!BBHHHBBH4s4s", payload[14:34])
    ttl=iphdr[5]
    prot= iphdr[6]

    print("%d %s -> %s \n %s \t %s" %(count,srcmac,dstmac,str(ttl),str(prot)))

    count+=1


