#include <linux/init.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter/x_tables.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/slab.h>
#include <linux/netdevice.h>
#include <linux/if_arp.h>
#include <linux/etherdevice.h>
#include <linux/skbuff.h>
#include <linux/inet.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>

#define DEVICE_NAME "arp_netfilter"
#define BUF_LEN 256

static struct nf_hook_ops arp_hook;

static char msg[BUF_LEN];

static unsigned int arp_filter_fn(void *priv,
                               struct sk_buff *skb,
                               const struct nf_hook_state *state)
{
    struct ethhdr *eth = eth_hdr(skb);
    struct arphdr *arp;

    printk(KERN_INFO "Ethernet!\n");

    if (ntohs(eth->h_proto) == ETH_P_ARP) {

        printk(KERN_INFO "ARP!\n");

        arp = (struct arphdr *)(skb->data + sizeof(struct ethhdr));

        if (arp->ar_op == ntohs(ARPOP_REQUEST)) {
            snprintf(msg, BUF_LEN, "ARP request: Sender IP: %pI4", &arp->ar_sip);
            // You can also use a method to send this to user space (via a socket or /proc)
            printk(KERN_INFO "%s\n", msg);
        }
    }

    return NF_ACCEPT;
}

static int __init arp_netfilter_init(void)
{
    arp_hook.hook = arp_filter_fn;
    arp_hook.pf = NFPROTO_ARP;
    arp_hook.hooknum = NF_ARP_IN;
    arp_hook.priority = NF_IP_PRI_FIRST;  // Adjust if needed

    nf_register_net_hook(&init_net, &arp_hook);

    printk(KERN_INFO "ARP Netfilter module loaded.\n");
    return 0;
}

static void __exit arp_netfilter_exit(void)
{
    nf_unregister_net_hook(&init_net, &nfho);
    printk(KERN_INFO "ARP Netfilter module unloaded.\n");
}

module_init(arp_netfilter_init);
module_exit(arp_netfilter_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Your Name");
MODULE_DESCRIPTION("Netfilter ARP Request Detector");