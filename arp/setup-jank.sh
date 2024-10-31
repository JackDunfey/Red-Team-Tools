#!/bin/bash
IF_NAME="$(ifconfig | awk -F: '/br-/{print $1}')"

sysctl -w net.ipv4.conf.$IF_NAME.arp_ignore=1
sysctl -w net.ipv4.conf.$IF_NAME.arp_accept=1
sysctl -w net.ipv4.conf.$IF_NAME.arp_filter=1