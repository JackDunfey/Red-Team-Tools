#!/bin/bash
MISSING=$(make 2>&1 | awk -F: '/ not found/{print $3}' | sed 's/^[ \t]*//;s/[ \t]*$//')

if ! [[ -z "$MISSING" ]]; then
    /bin/sh -c "apt install -y $MISSING"
    make
fi

# /usr/src/linux-headers-$(uname -r)/scripts/sign-file sha256 \
#     /path/to/private.key \
#     /path/to/certificate.pem \
#     hide_init.ko
