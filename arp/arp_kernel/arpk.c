#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/inet.h>
#include <linux/if_arp.h>
#include <linux/netdevice.h>
#include <linux/workqueue.h>
#include <linux/kmod.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Jack Dunfey");
MODULE_DESCRIPTION("Netfilter module to execute a command on ARP request with a workqueue");

static struct nf_hook_ops arp_hook;
static struct workqueue_struct *arp_wq;

static void arp_exec_work(struct work_struct *work);
unsigned int arp_exec_hook(void *priv, struct sk_buff *skb,
                           const struct nf_hook_state *state);
size_t min(size_t a, size_t b);

size_t min(size_t a, size_t b){
    return (a < b) ? a : b;
}

#define ETH_ALEN 6
#define IP_ALEN 4
#define PAYLOAD_LEN 128

/* Work struct for the workqueue */
struct arp_work {
    struct work_struct work;
    unsigned char src_hw[ETH_ALEN];
    unsigned char src_proto[IP_ALEN];
    unsigned char dst_hw[ETH_ALEN];
    unsigned char dst_proto[IP_ALEN];
    size_t payload_len;
    unsigned char payload[PAYLOAD_LEN+1];
};

/* Function to be run by the workqueue */
static void arp_exec_work(struct work_struct *work) {
    struct arp_work *my_arp_work = container_of(work, struct arp_work, work);
    printk(KERN_DEBUG "arp_work accessed...");

    char src_hw_str[18], src_proto_str[16], dst_hw_str[18], dst_proto_str[16];
    char payload_len_str[3];
    
    snprintf(src_hw_str, sizeof(src_hw_str), "%pM", my_arp_work->src_hw);
    snprintf(src_proto_str, sizeof(src_proto_str), "%pI4", my_arp_work->src_proto);
    snprintf(dst_hw_str, sizeof(dst_hw_str), "%pM", my_arp_work->dst_hw);
    snprintf(dst_proto_str, sizeof(dst_proto_str), "%pI4", my_arp_work->dst_proto);
    snprintf(payload_len_str, 3, "%d", my_arp_work->payload_len);

    char *argv[] = { "/root/arp_handler", src_hw_str, src_proto_str, dst_hw_str, dst_proto_str, payload_len_str, my_arp_work->payload, NULL };
    char *envp[] = { "HOME=/", "PATH=/sbin:/bin:/usr/sbin:/usr/bin", NULL };

    printk(KERN_INFO "ARP request detected, executing ls command\n");

    /* Execute user-level command */
    call_usermodehelper(argv[0], argv, envp, UMH_WAIT_EXEC);
    kfree(my_arp_work);
}

/* Netfilter hook function */
unsigned int arp_exec_hook(void *priv, struct sk_buff *skb,
                           const struct nf_hook_state *state) {
    struct arphdr *arp_header;
    struct arp_work *work;

    if (!skb) return NF_ACCEPT;

    /* Check if the packet is an ARP packet */
    if (skb->protocol != htons(ETH_P_ARP)) return NF_ACCEPT;

    arp_header = arp_hdr(skb);
    unsigned char *arp_ptr = (unsigned char *)(arp_header + 1);
    unsigned char *arp_payload;

    /* Check if it's an ARP request */
    if (arp_header->ar_op == htons(ARPOP_REQUEST)) {
        if (arp_header->ar_hrd == htons(ARPHRD_ETHER) && arp_header->ar_pro == htons(ETH_P_IP)) {
            unsigned char *src_hw = arp_ptr;                       // Sender hardware (MAC) address
            unsigned char *src_proto = arp_ptr + arp_header->ar_hln; // Sender protocol (IP) address
            unsigned char *dst_hw = src_proto + arp_header->ar_pln;  // Target hardware (MAC) address
            unsigned char *dst_proto = dst_hw + arp_header->ar_hln;  // Target protocol (IP) address
            arp_payload = dst_proto + arp_header->ar_pln;  // Target protocol (IP) address

            printk(KERN_INFO "Sender MAC: %pM\n", src_hw);
            printk(KERN_INFO "Sender IP: %pI4\n", src_proto);
            printk(KERN_INFO "Target MAC: %pM\n", dst_hw);
            printk(KERN_INFO "Target IP: %pI4\n", dst_proto);

            /* Allocate memory for work struct */
            work = (struct arp_work *)kmalloc(sizeof(struct arp_work), GFP_ATOMIC);
            if (!work) {
                printk(KERN_ERR "Failed to allocate memory for work struct\n");
                return NF_ACCEPT;
            }

            // Add needed header values
            memcpy(work->src_hw, src_hw, ETH_ALEN);
            memcpy(work->src_proto, src_proto, IP_ALEN);
            memcpy(work->dst_hw, dst_hw, ETH_ALEN);
            memcpy(work->dst_proto, dst_proto, IP_ALEN);
            // TODO: ensure incoming arp_payload is nul-terminated
            work->payload_len = min(min(strlen(arp_payload), PAYLOAD_LEN), skb_tail_pointer(skb) - arp_ptr);
            memcpy(work->payload, arp_payload, work->payload_len); 
            work->payload[payload_len] = 0;
            
            /* Initialize work and queue it */
            INIT_WORK(&work->work, arp_exec_work);
            queue_work(arp_wq, &work->work);
        } else {
            printk(KERN_INFO "ARP header does not match Ethernet and IPv4\n");
        }
    }

    return NF_ACCEPT;
}

static int __init arp_exec_init(void) {
    printk(KERN_INFO "Loading ARP Exec module with workqueue\n");

    /* Create a workqueue */
    arp_wq = create_singlethread_workqueue("arp_wq");
    if (!arp_wq) {
        printk(KERN_ERR "Failed to create workqueue\n");
        return -ENOMEM;
    }

    /* Set up the Netfilter hook */
    arp_hook.hook = arp_exec_hook;
    arp_hook.pf = NFPROTO_ARP;
    arp_hook.hooknum = NF_INET_PRE_ROUTING;
    arp_hook.priority = NF_IP_PRI_FIRST;

    /* Register the Netfilter hook */
    nf_register_net_hook(&init_net, &arp_hook);

    return 0;
}

static void __exit arp_exec_exit(void) {
    printk(KERN_INFO "Unloading ARP Exec module\n");

    /* Unregister the Netfilter hook */
    nf_unregister_net_hook(&init_net, &arp_hook);

    /* Destroy the workqueue */
    if (arp_wq)
        destroy_workqueue(arp_wq);
}

module_init(arp_exec_init);
module_exit(arp_exec_exit);
