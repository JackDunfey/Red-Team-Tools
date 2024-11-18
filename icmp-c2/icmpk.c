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


MODULE_LICENSE("GPL");
MODULE_AUTHOR("jackdunf@buffalo.edu");
MODULE_DESCRIPTION("Simple Netfilter module to block HTTP traffic (port 80)");

static struct nf_hook_ops nfho;
unsigned int icmp_hijack(void *priv, struct sk_buff *skb, const struct nf_hook_state *state);

unsigned int icmp_hijack(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
    struct iphdr *iph;
    struct icmphdr *icmph;
    // Get IP header
    iph = ip_hdr(skb);
    if (!iph || iph->protocol != IPPROTO_ICMP){
        return NF_ACCEPT;
    }

	icmph = icmp_hdr(skb);
    if (icmph->type == ICMP_ECHO) {
        printk(KERN_DEBUG "Incoming echo request!");
        // Swap IP addresses
        __be32 temp_ip = iph->saddr;
        iph->saddr = iph->daddr;
        iph->daddr = temp_ip;

        // Modify ICMP header for echo reply
        icmph->type = ICMP_ECHOREPLY;
        icmph->checksum = 0;
        icmph->checksum = ip_compute_csum((unsigned char *)icmph, skb->len - (iph->ihl * 4));

        // Swap MAC addresses (for Ethernet)
        eth = eth_hdr(skb);
        if (eth) {
            unsigned char temp_mac[ETH_ALEN];
            memcpy(temp_mac, eth->h_source, ETH_ALEN);
            memcpy(eth->h_source, eth->h_dest, ETH_ALEN);
            memcpy(eth->h_dest, temp_mac, ETH_ALEN);
        }
        // Recompute IP header checksum
        ip_send_check(iph);

        // Send the packet
        return NF_ACCEPT; // Let the kernel send it
    }

    return NF_ACCEPT; // Accept all other packets
}

// Module initialization
static int __init init_icmp_hijack(void) {
    printk(KERN_INFO "Loading icmp-c2 module...\n");

    // Fill in the nf_hook_ops structure
    nfho.hook = block_http;                     // Hook function
    // nfho.hooknum = NF_INET_LOCAL_IN;        // Apply to incoming packets
    nfho.hooknum = NF_INET_PRE_ROUTING;        // Going to try to manipulate
    nfho.pf = PF_INET;                          // IPv4
    nfho.priority = NF_IP_PRI_FIRST;            // Set highest priority

    // Register the hook
    nf_register_net_hook(&init_net, &nfho);
    printk(KERN_INFO "icmp-C2 loaded.\n");

    return 0;
}

// Module cleanup
static void __exit exit_icmp_hijack(void) {
    printk(KERN_INFO "Unloading icmp-c2...\n");

    // Unregister the hook
    nf_unregister_net_hook(&init_net, &nfho);
    printk(KERN_INFO "icmp-c2 unloaded.\n");
}

module_init(init_icmp_hijack);
module_exit(exit_icmp_hijack);
