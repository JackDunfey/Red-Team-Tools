# Disable SYN cookies (protection against SYN flood attacks)
sysctl -w net.ipv4.tcp_syncookies=0

# Disable Address Space Layout Randomization (ASLR)
sysctl -w kernel.randomize_va_space=0

# Enable IP forwarding (can make a machine act as a router, potential vector for attacks)
sysctl -w net.ipv4.ip_forward=1

# Disable ICMP echo ignore broadcast (vulnerable to broadcast amplification attacks)
sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=0

# Enable source routing (can be exploited for redirecting traffic)
sysctl -w net.ipv4.conf.all.accept_source_route=1
sysctl -w net.ipv4.conf.default.accept_source_route=1

# Disable IP spoofing protection
sysctl -w net.ipv4.conf.all.rp_filter=0
sysctl -w net.ipv4.conf.default.rp_filter=0

# Accept ICMP redirects (can allow route injection attacks)
sysctl -w net.ipv4.conf.all.accept_redirects=1
sysctl -w net.ipv4.conf.default.accept_redirects=1

# Accept secure ICMP redirects (can still lead to malicious redirection)
sysctl -w net.ipv4.conf.all.secure_redirects=1
sysctl -w net.ipv4.conf.default.secure_redirects=1

# Disable TCP timestamp (may expose system uptime and be used in fingerprinting attacks)
sysctl -w net.ipv4.tcp_timestamps=1

# Reduce the size of the connection backlog queue, making it more susceptible to DoS attacks

sysctl -w net.ipv4.tcp_max_syn_backlog=64
sysctl -w net.core.somaxconn=64
sysctl -w net.core.netdev_max_backlog=64

# Lower the maximum number of open files (resource exhaustion risk)
sysctl -w fs.file-max=1024

# Disable Kernel Protection for Hard and Soft Links
sysctl -w fs.protected_hardlinks=0
sysctl -w fs.protected_symlinks=0

# Enable Core Dumps for Set-UID Programs (probably won't be used)
# sysctl -w fs.suid_dumpable=1

# Allow non-privileged users to read dmesg
# sysctl -w kernel.dmesg_restrict=0


# Disable Kernel Page Table Isolation (KPTI)
sysctl -w kernel.kpti=0

# Enable Transparent Huge Pages
sysctl -w vm.nr_hugepages=0

# Lower the Dirty Ratio and Dirty Background Ratio
sysctl -w vm.dirty_ratio=5
sysctl -w vm.dirty_background_ratio=5
