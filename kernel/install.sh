#!/bin/bash

# Source: https://wiki.ubuntu.com/Kernel/BuildYourOwnKernel

# OS_RELEASE=""

# jammy =  Ubuntu 22.04 LTS
# Put these at top
deb-src http://archive.ubuntu.com/ubuntu jammy main
deb-src http://archive.ubuntu.com/ubuntu jammy-updates main


# Install dependencies 
apt build-dep -y linux linux-image-unsigned-$(uname -r)
apt install -y libncurses-dev gawk flex bison openssl libssl-dev dkms libelf-dev libudev-dev libpci-dev libiberty-dev autoconf llvm debhelper rustc bindgen-0.65

# Install source code
apt source -y linux-image-unsigned-$(uname -r)

<< EOF
The build process uses a configuration that is put together from various sub-config files. The simplest way to modify anything here is to run the commands below. This takes the current configuration for each architecture/flavour supported and calls menuconfig to edit its config file. The chmod is needed only if you obtain the source by apt rather than git, because the way the source package is created, it loses the executable bits on the scripts.:
EOF

<< EOF
Add something like "+test1" to the end of the first version number in the debian.master/changelog file, before building
EOF
chmod a+x debian/rules
chmod a+x debian/scripts/*
chmod a+x debian/scripts/misc/*
fakeroot debian/rules clean
cp /boot/config-' uname -r ' .config

fakeroot make -j$(nproc) && fakeroot make modules_install -j$(nproc) && make install

# # BUILDING THE KERNEL
# fakeroot debian/rules clean
# # quicker build:
# fakeroot debian/rules binary-headers binary-generic binary-perarch
# # if you need linux-tools or lowlatency kernel, run instead:
# fakeroot debian/rules binary

# cd ..
# ls *.deb
# # On later releases, you will also find a linux-extra- package which you should also install if present.

# # To install:
# dpkg -i linux*4.8.0-17.19*.deb # will need to change the numbers likely