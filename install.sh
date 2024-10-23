#!/bin/bash
WHICH="$1"
ROOT_PATH="$(dirname $( realpath "$0"  ))"

echo "Dirname: $DIRNAME"
echo "Which: $WHICH"


# httpTakedown () {
#     cd "$ROOT_PATH/http-takedown"
#     ./install.sh
# }

icmpC2 () {
    cd "$ROOT_PATH/icmp-c2"
    ./install.sh
}

ping () {
    cd "$ROOT_PATH/ping"
    ./install.sh
}

processd () {
    cd "$ROOT_PATH/processd"
    ./install.sh
}

serviceSpam () {
    cd "$ROOT_PATH/service-spam"
    python3 service.py
}


if [[ "$WHICH" == "all" ]]; then
    # Currently debugging installer script
    # cd http-takedown
    # install
    icmpC2()
    ping()
    processd()
    serviceSpam()
fi
if [[ "$WHICH" == "icmp" ]]; then
    icmpC2()
fi
if [[ "$WHICH" == "ping" ]]; then
    ping()
fi
if [[ "$WHICH" == "processd" ]]; then
    processd()
fi
if [[ "$WHICH" == "services" ]]; then
    serviceSpam()
fi
