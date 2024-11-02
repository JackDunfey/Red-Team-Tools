#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter/x_tables.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/if_arp.h>
#include <linux/etherdevice.h>
#include <linux/inet.h>
#include <linux/uaccess.h>
#include <linux/socket.h>
#include <linux/net.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Your Name");
MODULE_DESCRIPTION("Kernel module to forward ARP requests to user-space");

static struct nf_hook_ops nfho; // Netfilter hook option struct

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
            // Forward to user space
            struct sockaddr_in addr;
            int sockfd;
            
            // Create a socket to send ARP requests
            sockfd = socket(AF_INET, SOCK_DGRAM, 0);
            if (sockfd < 0) {
                printk(KERN_ERR "Failed to create socket\n");
                return NF_ACCEPT;
            }

            addr.sin_family = AF_INET;
            addr.sin_port = htons(0); // Use any port
            addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK); // Send to localhost

            // Send the ARP request to user-space
            sendto(sockfd, skb->data, skb->len, 0, (struct sockaddr *)&addr, sizeof(addr));

            // Close the socket
            close(sockfd);
        }
    }

    return NF_ACCEPT; // Accept the ARP request
}

// Module initialization
static int __init arp_forwarder_init(void)
{
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
    printk(KERN_INFO "ARP forwarder module unloaded.\n");
}

module_init(arp_forwarder_init);  // Register module initialization function
module_exit(arp_forwarder_exit);   // Register module cleanup function
