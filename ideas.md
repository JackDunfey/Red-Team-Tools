# Lockdown Ideas & Notes
<hr />

## File stuff

To set edit time of file:
- `touch -t <info> <filename>`

Cut blocks from file:
- `dd skip=<start> count=<# of blocks> bs=8 if=file of=file`

Create a file of random bytes:
- `dd if=/dev/random of=<filename> bs=<block size> count=<# of blocks>`

## Cover Your Tracks:
```
echo "" > /var/log/auth.log
rm ~/.bash_history -rf
export HISTFILESIZE=0
export HISTSIZE=0
unset HISTFILE
ln /dev/null ~/.bash_history -sf
kill -9 $$ # kill current process
```

## System Configuration Files
<table>
    <thead>
        <tr>
            <th>Filename</th>
            <th>Description</th>
        </tr>
    </thead>
    <tbody>
        <tr>
            <td><code>/etc/init.d</code></td>
            <td>Startup scripts</td>
        </tr>
        <tr>
            <td><code>/etc/hosts</code></td>
            <td>DNS static</td>
        </tr>
        <tr>
            <td><code>/etc/network/interfaces</code></td>
            <td>Network config</td>
        </tr>
        <tr>
            <td><code>/etc/profile</code></td>
            <td>System env variables (like PATH)</td>
        </tr>
        <tr>
            <td><code>/etc/apt/sources.list</code></td>
            <td>Can create a fake mirror</td>
        </tr>
        <tr>
            <td><code>/etc/resolv.conf</code></td>
            <td>DNS config</td>
        </tr>
        <tr>
            <td><code>/etc/fstab</code></td>
            <td>File system info</td>
        </tr>
    </tbody>
</table>

## C2 ideas
- Port Knocking (`fwknop`)
- ftp backdoor
- http->arp C2 (Utlimate-c2)

## Misc Projects
- pam_unix/VerySecure

# Tips & Tricks
<hr />

## Hiding
- `unset HISTFILE`

## Persistence

`at(1)` can be used as cron alternative

# To Research
<hr />

## Hiding
- How is Mythic hidden?

## Persistence
- Add persistence loop <--
	- implement a runonce vs run kind of system on startup (service)
- Add users

## General

- smb & share (windows share)
- rdesktop
- remotely record mic with ssh (page 6)
- SSH callback (page 9)

<!-- - init 6 = reboot, init 0 = shutdown -->

Ideas for Lockdown:
- embed iframe on HTML
- add apache login to their websites, so scoring engine will fail
- 72
- Modify primary DNS server to a machine I control
- !! - ip addr add ... - add hidden network interfaces
- modify path [found with which]

- Attach a bad disk (vSphere and mount)

# Windows

## System Files
<table>
    <thead>
        <tr>
            <th>Filename</th>
            <th>Description</th>
        </tr>
    </thead>
    <tbody>
        <tr>
            <td><code>%SYSTEMROOT%\System32\drivers\etc\hosts</code></td>
            <td>DNS static</td>
        </tr>
        <tr>
            <td><code>%SYSTEMROOT%\System32\drivers\etc\networks</code></td>
            <td>Network config</td>
        </tr>
        <tr>
            <td><code>%SYSTEMROOT%\System32\config\SAM</code></td>
            <td>Password hashes</td>
        </tr>
        <tr>
            <td><code>%ALLUSERSPROFILE%\Start Menu\Programs\Startup</code></td>
            <td>Directory of startup executables</td>
        </tr>
        <tr>
            <td><code>%USERPROFILE%\Start Menu\Programs\Startup</code></td>
            <td>Directory of startup executables</td>
        </tr>
    </tbody>
</table>

## Networking 

##### DNS
Use alternate DNS server (macine red team controls or non-existant one)
`netsh interface ip set dns local static <ip>`

##### Change  IP address
Use DHCP
`netsh interface ip set dns local static <ip>`
Use static:
`netsh interface ip set address name="Ethernet" static 192.168.1.100 255.255.255.0 192.168.1.1`

## Disable CMD/Powershell

#### For just CMD
For all users, replace `HKCU` with `HKLM`
`reg add HKCU\Software\Policies\Microsoft\Windows\System /v DisableCMD /t REG_DWORD /d 1 /f`

#### For Both
Prevent execution:
`reg add HKLM\Software\Policies\Microsoft\Windows\System /v EnableScripts /t REG_DWORD /d 0 /f`

Prevent Powershell from Running:
<code>reg add HKLM\Software\Policies\Microsoft\Windows\System /v DisallowRun /t REG_DWORD /d 1 /f
reg add HKLM\Software\Policies\Microsoft\Windows\System\DisallowRun /v 1 /t REG_SZ /d powershell.exe /f
reg add HKLM\Software\Policies\Microsoft\Windows\System\DisallowRun /v 2 /t REG_SZ /d pwsh.exe /f
</code>


## Powershell Notes

page 22-25

## Registry Keys

autoadminlogon, Security\Policy\Secrets

##### Startup Locations
Local Machine:
- `HKLM\Software\Microsoft\Windows\CurrentVersion\Run & \Runonce`
- `HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run`

Current User:
- `HKCU\Software\Microsoft\Windows\CurrentVersion\Run & \Runonce`
- `HKCU\Software\Microsoft\Windows NT\CurrentVersion\Windows\Load & \Run`

## lockout.bat
```
@echo Test run:
for /f %%U in (list.txt) do @for /l %%C in (1,1,5) do @echo net use \\WIN-1234\c$ /USER:%%U wrongpass
```

## Task Scheduler

page 32

## Networking

Common ports on pg 35

