#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/if_arp.h>

static unsigned int arp_filter_hook(void *priv,
                                     struct sk_buff *skb,
                                     const struct nf_hook_state *state) {
    struct ethhdr *eth = eth_hdr(skb);
    struct arphdr *arp;

    if (ntohs(eth->h_proto) == ETH_P_ARP) {
        arp = (struct arphdr *)(skb->data + sizeof(struct ethhdr));
        if (arp->op == htons(ARPOP_REPLY)) {
            printk(KERN_INFO "Filtered outgoing ARP reply\n");
            return NF_DROP; // Drop the ARP reply
        }
    }
    return NF_ACCEPT; // Accept other packets
}

static struct nf_hook_ops arp_filter_ops = {
    .hook = arp_filter_hook,
    .pf = PF_INET,
    .hooknum = NF_INET_POST_ROUTING,
    .priority = NF_IP_PRI_FIRST, // Set priority
};

static int __init arp_filter_init(void) {
    nf_register_net_hook(&init_net, &arp_filter_ops);
    printk(KERN_INFO "ARP filter module loaded\n");
    return 0;
}

static void __exit arp_filter_exit(void) {
    nf_unregister_net_hook(&init_net, &arp_filter_ops);
    printk(KERN_INFO "ARP filter module unloaded\n");
}

module_init(arp_filter_init);
module_exit(arp_filter_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Your Name");
MODULE_DESCRIPTION("A simple ARP reply filter");
