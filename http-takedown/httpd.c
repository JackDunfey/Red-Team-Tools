#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/ktime.h>
#include <linux/jiffies.h>
#include <linux/uaccess.h>
#include <linux/inet.h>
#include <linux/skbuff.h>
#include <linux/net.h>
#include <linux/inet.h>
#include <linux/if_ether.h>


#define SECONDS_BETWEEN_HTTP_OUTAGE 120  //  2 min
#define SECONDS_DURING_HTTP_OUTAGE 300   //  5 min

// Total of 16% of the time

MODULE_LICENSE("GPL");
MODULE_AUTHOR("jackdunf@buffalo.edu");
MODULE_DESCRIPTION("Simple Netfilter module to block HTTP traffic (port 80)");

unsigned int block_http(void *priv, struct sk_buff *skb, const struct nf_hook_state *state);
int should_block_http(void);

// Netfilter hook options
static struct nf_hook_ops nfho;
static struct timespec64 last_time; 

static int toggle_value = 1;
int should_block_http(void) {
    struct timespec64 current_time;
    ktime_get_real_ts64(&current_time);
    time64_t delta = current_time.tv_sec - last_time.tv_sec;
    if (delta >= (toggle_value ? SECONDS_DURING_HTTP_OUTAGE : SECONDS_BETWEEN_HTTP_OUTAGE)){
        toggle_value = !toggle_value;
        last_time = current_time;
    }
    printk(KERN_INFO "Blocking HTTP? %d\n", toggle_value);
    return toggle_value;
}



// Hook function to filter outgoing packets
unsigned int block_http(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {

    struct iphdr *iph;
    struct tcphdr *tcph;

    // Get IP header
    iph = ip_hdr(skb);
    if (!iph || iph->protocol != IPPROTO_TCP)
        return NF_ACCEPT;

    // We only care about TCP packets
    // tcph = (struct tcphdr *)((unsigned char *)iph + (iph->ihl * 4));
    tcph = tcp_hdr(skb);
    
    if (ntohs(tcph->dest) == 80) {
        printk(KERN_INFO "HTTP Packet from %pI4... ", &iph->saddr);
        if(should_block_http()){
            printk(KERN_INFO "Dropping\n");
            return NF_DROP; // DROP the packet
        }
        printk(KERN_INFO "Accepted\n");
    } else {
        printk(KERN_INFO "Non-HTTP packet... %d, %d\n", ntohs(tcph->dest), tcph->dest);
    }

    return NF_ACCEPT; // Accept all other packets
}

// Module initialization
static int __init init_block_http(void) {
    printk(KERN_INFO "Loading HTTP blocking module...\n");
    ktime_get_real_ts64(&last_time);            // Initialize time

    // Fill in the nf_hook_ops structure
    nfho.hook = block_http;                     // Hook function
    nfho.hooknum = NF_INET_LOCAL_IN;        // Apply to incoming packets
    nfho.pf = PF_INET;                          // IPv4
    nfho.priority = NF_IP_PRI_FIRST;            // Set highest priority

    // Register the hook
    nf_register_net_hook(&init_net, &nfho);
    printk(KERN_INFO "HTTP blocking module loaded.\n");

    return 0;
}

// Module cleanup
static void __exit exit_block_http(void) {
    printk(KERN_INFO "Unloading HTTP blocking module...\n");

    // Unregister the hook
    nf_unregister_net_hook(&init_net, &nfho);
    printk(KERN_INFO "HTTP blocking module unloaded.\n");
}

module_init(init_block_http);
module_exit(exit_block_http);



// Notes: Ensure this is compiled using the same compiler as the kernel
// Example: sudo apt install gcc-12 g++-12
// Make sure that is the used gcc: export CC=/usr/bin/gcc-12

/*  Insert:
 -  sudo insmod block_http.ko
    Verify:
 -  lsmod | grep block_http
    Remove:
 -  sudo rmmod block_http
*/