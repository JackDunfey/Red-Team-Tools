apt install -y autoconf automake autopoint bison gperf m4 texinfo textlive
.bootstrap
FORCE_UNSAFE_CONFIGURE=1 ./configure
# replace ls
# fix factor.c
make src/ls