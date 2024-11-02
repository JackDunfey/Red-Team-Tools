#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/inet.h>
#include <linux/if_arp.h>
#include <linux/netdevice.h>
#include <linux/unistd.h>
#include <linux/kmod.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Your Name");
MODULE_DESCRIPTION("Netfilter module to execute a command on ARP request");

static struct nf_hook_ops arp_hook;

unsigned int arp_exec_hook(void *priv, struct sk_buff *skb,
                           const struct nf_hook_state *state) {
    struct arphdr *arp_header;

    if (!skb) return NF_ACCEPT;

    /* Check if the packet is an ARP packet */
    if (skb->protocol != htons(ETH_P_ARP)) return NF_ACCEPT;

    arp_header = arp_hdr(skb);

    /* Check if it's an ARP request */
    if (arp_header->ar_op == htons(ARPOP_REQUEST)) {
        /* Define the command to run */
        char *argv[] = { "/bin/ls", NULL };
        char *envp[] = { "HOME=/", "PATH=/sbin:/bin:/usr/sbin:/usr/bin", NULL };

        printk(KERN_INFO "ARP request detected, executing ls command\n");

        /* Execute user-level command */
        call_usermodehelper(argv[0], argv, envp, UMH_WAIT_EXEC);
    }

    return NF_ACCEPT;
}

static int __init arp_exec_init(void) {
    printk(KERN_INFO "Loading ARP Exec module\n");

    arp_hook.hook = arp_exec_hook;
    arp_hook.pf = NFPROTO_ARP;
    arp_hook.hooknum = NF_ARP_IN;
    arp_hook.priority = NF_IP_PRI_FIRST;

    /* Register the Netfilter hook */
    nf_register_net_hook(&init_net, &arp_hook);
    return 0;
}

static void __exit arp_exec_exit(void) {
    printk(KERN_INFO "Unloading ARP Exec module\n");

    /* Unregister the Netfilter hook */
    nf_unregister_net_hook(&init_net, &arp_hook);
}

module_init(arp_exec_init);
module_exit(arp_exec_exit);
