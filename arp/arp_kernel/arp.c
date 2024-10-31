#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_arp.h>
#include <linux/if_arp.h>
#include <linux/if_ether.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/netfilter_ipv4.h>

static struct nf_hook_ops arp_hook;

unsigned int arp_filter_fn(void *priv, struct sk_buff *skb, const struct nf_hook_state *state);

unsigned int arp_filter_fn(void *priv, struct sk_buff *skb,
                            const struct nf_hook_state *state) {
    
    printk(KERN_INFO "At least the function started!\n");

    struct ethhdr *eth;
    struct arphdr *arp;
    struct sk_buff *reply_skb;
    struct net_device *dev;
    unsigned char *reply_ptr;

    eth = eth_hdr(skb);
    if (eth->h_proto != htons(ETH_P_ARP)) {
        printk(KERN_INFO "\t\tNot ARP!\n");
        return NF_ACCEPT;  // Not an ARP packet, let it pass
    }

    arp = arp_hdr(skb);
    if (arp->ar_op == htons(ARPOP_REQUEST)) {

        printk(KERN_INFO "It's an ARP!\n");

        // Create an ARP reply
        dev = dev_get_by_name(&init_net, "br-5e22667e4604");  // Replace "eth0" with your actual interface name
        if (!dev) {
            printk(KERN_ERR "Device not found :(\n");
            return NF_ACCEPT;  // Device not found, let it pass
        }

        reply_skb = alloc_skb(sizeof(struct ethhdr) + sizeof(struct arphdr), GFP_ATOMIC);
        if (!reply_skb) {
            printk(KERN_ERR "Couldn't allocate reply_skb :(\n");
            dev_put(dev);
            return NF_ACCEPT;  // Allocation failed, let it pass
        }

        skb_reserve(reply_skb, sizeof(struct ethhdr));  // Reserve space for Ethernet header

        // Fill in the Ethernet header
        reply_ptr = skb_put(reply_skb, sizeof(struct ethhdr));
        memcpy(reply_ptr, eth, sizeof(struct ethhdr));  // Copy source MAC
        memcpy(reply_ptr + ETH_ALEN, eth->h_dest, ETH_ALEN);  // Copy destination MAC
        eth->h_proto = htons(ETH_P_ARP);  // Set ARP protocol

        // Fill in the ARP reply
        struct arphdr *reply_arp = (struct arphdr *)(reply_ptr + sizeof(struct ethhdr));
        memcpy(reply_arp, arp, sizeof(struct arphdr));  // Copy ARP header
        reply_arp->ar_op = htons(ARPOP_REPLY);  // Set operation to reply

        // Set the sender and target IP/MAC addresses (modify as necessary)
        memcpy(reply_arp->ar_tha, arp->ar_sha, ETH_ALEN);  // Target hardware address
        memcpy(reply_arp->ar_sha, dev->dev_addr, ETH_ALEN);  // Sender hardware address

        memcpy(reply_arp->ar_sip, arp->ar_tip, sizeof(reply_arp->ar_sip)); // Copy target IP to sender IP
        memcpy(reply_arp->ar_tip, arp->ar_sip, sizeof(reply_arp->ar_tip)); // Copy sender IP to target IP

        // reply_arp->ar_sip = arp->ar_tip;  // Sender IP address
        // reply_arp->ar_tip = arp->ar_sip;  // Target IP address

        // Prepare and send the reply
        reply_skb->dev = dev;  // Set the device for the packet
        reply_skb->protocol = htons(ETH_P_ARP);  // Set protocol
        dev_kfree_skb(skb);  // Free the original packet
        dev_queue_xmit(reply_skb);  // Send the reply
        dev_put(dev);  // Release the device reference

        printk(KERN_INFO "We did that!\n");
        // Drop the original ARP request
        return NF_DROP;
    }

    return NF_ACCEPT;  // Accept all other ARP packets
}

static int __init arp_filter_init(void) {

    printk(KERN_INFO "jackdunf - initing...");

    arp_hook.hook = arp_filter_fn;
    arp_hook.pf = NFPROTO_ARP;
    arp_hook.hooknum = NF_ARP_IN;
    arp_hook.priority = NF_IP_PRI_FIRST;  // Adjust if needed

    nf_register_net_hook(&init_net, &arp_hook);
    printk(KERN_INFO "ARP filter module loaded.\n");
    return 0;
}

static void __exit arp_filter_exit(void) {
    nf_unregister_net_hook(&init_net, &arp_hook);
    printk(KERN_INFO "ARP filter module unloaded.\n");
}

module_init(arp_filter_init);
module_exit(arp_filter_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Jack Dunfey");
MODULE_DESCRIPTION("Custom ARP Filtering Kernel Module that Replies Before Dropping");

// Note: had to modify kernel if_arp.h library (uncomment some lines)