#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/if_arp.h>

// Define hook options
static struct nf_hook_ops arp_hook;

unsigned int arp_filter_fn(void *priv, struct sk_buff *skb,
                           const struct nf_hook_state *state) {
    struct ethhdr *eth;
    struct arphdr *arp;

    // Ensure packet is ARP
    eth = eth_hdr(skb);
    if (eth->h_proto != htons(ETH_P_ARP)) {
        return NF_ACCEPT;  // Not an ARP packet, so ignore
    }

    // Extract ARP header and implement filtering logic
    arp = arp_hdr(skb);
    if (arp->ar_op == htons(ARPOP_REPLY)) {
        // Example: Drop requests not from a specific IP/MAC or other conditions
        return NF_DROP;
    }

    return NF_ACCEPT;  // Allow packet if conditions aren't met
}

static int __init arp_filter_init(void) {
    arp_hook.hook = arp_filter_fn;
    arp_hook.pf = NFPROTO_ARP;
    arp_hook.hooknum = NF_ARP_OUT;
    arp_hook.priority = NF_IP_PRI_FIRST;

    nf_register_net_hook(&init_net, &arp_hook);  // Register hook
    return 0;
}

static void __exit arp_filter_exit(void) {
    nf_unregister_net_hook(&init_net, &arp_hook);  // Unregister hook
}

module_init(arp_filter_init);
module_exit(arp_filter_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Jack Dunfey");
MODULE_DESCRIPTION("Custom ARP Filtering Kernel Module");
