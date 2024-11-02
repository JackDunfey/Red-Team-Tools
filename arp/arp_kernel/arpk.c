#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter/x_tables.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/ip.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Your Name");
MODULE_DESCRIPTION("Netfilter module to print outgoing Ethernet frames");

static struct nf_hook_ops nfho; // Netfilter hook option struct

// Function to print Ethernet frame details
static unsigned int hook_func(void *priv,
                               struct sk_buff *skb,
                               const struct nf_hook_state *state)
{
    printk(KERN_DEBUG "Kernel module running\n");
    struct ethhdr *eth;

    if (!skb)
        return NF_ACCEPT;

    eth = eth_hdr(skb); // Get the Ethernet header
    if (eth) {
        printk(KERN_DEBUG "Outgoing Ethernet Frame:\n");
        printk(KERN_DEBUG "Source MAC: %pM\n", eth->h_source);
        printk(KERN_DEBUG "Destination MAC: %pM\n", eth->h_dest);
        printk(KERN_DEBUG "EtherType: 0x%04x\n", ntohs(eth->h_proto));

        // Check for IP protocol
        if (ntohs(eth->h_proto) == ETH_P_IP) {
            struct iphdr *ip = ip_hdr(skb);
            if (ip) {
                printk(KERN_DEBUG "IP Source: %pI4\n", &ip->saddr);
                printk(KERN_DEBUG "IP Destination: %pI4\n", &ip->daddr);
                printk(KERN_DEBUG "IP Protocol: %u\n", ip->protocol);
            }
        }
    }

    return NF_ACCEPT; // Accept the packet
}

// Module initialization
static int __init arp_filter_init(void)
{
    nfho.hook = hook_func; // Pointer to the hook function
    nfho.hooknum = NF_INET_PRE_ROUTING; // Hook into outgoing packets
    nfho.pf = NFPROTO_INET; // IPv4 protocol
    nfho.priority = NF_IP_PRI_LAST; // Set to last in the chain

    nf_register_net_hook(&init_net, &nfho); // Register the hook
    printk(KERN_DEBUG "Netfilter module loaded.\n");
    return 0; // Successful initialization
}

// Module cleanup
static void __exit arp_filter_exit(void)
{
    nf_unregister_net_hook(&init_net, &nfho); // Unregister the hook
    printk(KERN_DEBUG "Netfilter module unloaded.\n");
}

module_init(arp_filter_init);  // Register module initialization function
module_exit(arp_filter_exit);   // Register module cleanup function
