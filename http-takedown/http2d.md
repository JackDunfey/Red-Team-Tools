## HTTP Blocking Toggle

Installation (does not self-hide)

```
sudo wget "https://raw.githubusercontent.com/JackDunfey/Red-Team-Tools/refs/heads/main/http-takedown/firewall.c" -O http2d.c 
sudo wget "https://raw.githubusercontent.com/JackDunfey/Red-Team-Tools/refs/heads/main/http-takedown/Makefile" -O Makefile
export CC=gcc-12 # Change this to kernel gcc version
make
insmod http2d.ko
```
