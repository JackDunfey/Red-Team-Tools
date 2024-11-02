#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter/x_tables.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/if_arp.h>
#include <linux/etherdevice.h>
#include <linux/netlink.h>
#include <linux/slab.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Your Name");
MODULE_DESCRIPTION("Kernel module to forward ARP requests to user-space");

#define NETLINK_USER 31

static struct nf_hook_ops nfho; // Netfilter hook option struct
static struct sock *nl_sk = NULL; // Netlink socket

// Function to handle ARP requests
static unsigned int arp_hook_func(void *priv,
                                   struct sk_buff *skb,
                                   const struct nf_hook_state *state)
{
    struct ethhdr *eth = eth_hdr(skb);
    
    // Check if the packet is an ARP request
    if (ntohs(eth->h_proto) == ETH_P_ARP) {
        struct arphdr *arp = (struct arphdr *)(skb->data + sizeof(struct ethhdr));

        // Check if the packet is an ARP request
        if (ntohs(arp->ar_op) == ARPOP_REQUEST) {
            struct nlmsghdr *nlh;
            int msg_size = skb->len; // Length of the ARP packet
            char *msg = (char *)kmalloc(msg_size, GFP_KERNEL);
            if (!msg) {
                printk(KERN_ERR "Failed to allocate memory for message\n");
                return NF_ACCEPT;
            }
            memcpy(msg, skb->data, msg_size); // Copy ARP request data
            
            nlh = nlmsg_new(msg_size, GFP_KERNEL);
            if (!nlh) {
                printk(KERN_ERR "Failed to allocate netlink message\n");
                kfree(msg);
                return NF_ACCEPT;
            }

            // Populate netlink message with ARP request data
            memcpy(nlmsg_data(nlh), msg, msg_size);
            nlh->nlmsg_len = NLMSG_LENGTH(msg_size); // Set the message length
            nlh->nlmsg_flags = 0; // Set flags (optional)
            nlh->nlmsg_type = 0; // Set type (optional)
            nlh->nlmsg_seq = 0; // Set sequence number (optional)
            nlh->nlmsg_pid = 0; // Set PID (optional)
            
            // Send netlink message to user space
            netlink_unicast(nl_sk, nlh, 0, MSG_DONTWAIT);
            kfree(msg); // Free the allocated memory
        }
    }

    return NF_ACCEPT; // Accept the ARP request
}

// Netlink socket initialization
static void setup_netlink(void) {
    struct netlink_kernel_cfg cfg = {
        .input = NULL, // No need for input handler in this case
    };
    nl_sk = netlink_kernel_create(&init_net, NETLINK_USER, &cfg);
    if (!nl_sk) {
        printk(KERN_ALERT "Error creating netlink socket.\n");
    }
}

// Module initialization
static int __init arp_forwarder_init(void)
{
    setup_netlink();
    
    nfho.hook = arp_hook_func; // Pointer to the hook function
    nfho.hooknum = NF_INET_PRE_ROUTING; // Hook into incoming packets
    nfho.pf = NFPROTO_INET; // IPv4 protocol
    nfho.priority = NF_IP_PRI_FIRST; // Set to first in the chain

    nf_register_net_hook(&init_net, &nfho); // Register the hook
    printk(KERN_INFO "ARP forwarder module loaded.\n");
    return 0; // Successful initialization
}

// Module cleanup
static void __exit arp_forwarder_exit(void)
{
    nf_unregister_net_hook(&init_net, &nfho); // Unregister the hook
    netlink_kernel_release(nl_sk); // Release the netlink socket
    printk(KERN_INFO "ARP forwarder module unloaded.\n");
}

module_init(arp_forwarder_init);  // Register module initialization function
module_exit(arp_forwarder_exit);   // Register module cleanup function
