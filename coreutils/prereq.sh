# Update this
RED_TEAM_TOOLS_DIR="/root/Red-Team-Tools" 

sed -i -e 's/# deb-src/deb-src/' /etc/apt/sources.list
apt update
apt-get source coreutils && apt-get build-dep coreutils
apt install -y build-essential autoconf automake autopoint bison gperf m4 texinfo gettext gawk libtool-bin
cd coreutils-*
cp "$RED_TEAM_TOOLS_DIR/coreutils/ls.c" src/ls.c
autoreconf -fiv
FORCE_UNSAFE_CONFIGURE=1 ./configure --prefix=/usr --disable-silent-rules
make -j$(nproc)