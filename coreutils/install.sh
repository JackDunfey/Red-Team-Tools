#!/bin/bash
if [[ $(id -u) != "0" ]]; then
    echo "Must run as root"
    exit 1
fi
apt update
apt install -y autoconf automake autopoint bison gperf m4 texinfo texlive
make
# mv src/ls $(which ls)