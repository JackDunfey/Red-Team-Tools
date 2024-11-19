#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/socket.h>
#include <linux/net.h>
#include <linux/in.h>
#include <linux/inet.h>
#include <linux/slab.h>
#include <linux/skbuff.h>
#include <net/sock.h>
#include <linux/icmp.h>
#include <linux/ip.h>
#include <linux/errno.h>

#define ICMP_ECHO 8
#define ICMP_REPLY 0
#define ICMP_HDR_SIZE 8
#define PAYLOAD "Hello from kernel"
#define PAYLOAD_SIZE sizeof(PAYLOAD)
#define PACKET_SIZE (ICMP_HDR_SIZE + PAYLOAD_SIZE)

struct socket *raw_socket;

static uint16_t checksum(uint16_t *data, int len) {
    uint32_t sum = 0;

    while (len > 1) {
        sum += *data++;
        len -= 2;
    }

    if (len == 1)
        sum += *(uint8_t *)data;

    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);

    return (uint16_t)~sum;
}

static int send_icmp_echo_request(void) {
    struct sockaddr_in dest_addr;
    struct msghdr msg = {};
    struct kvec iov;
    char *packet;
    struct icmphdr *icmp_hdr;
    int ret = 0;

    // Allocate memory for the packet
    packet = kmalloc(PACKET_SIZE, GFP_KERNEL);
    if (!packet)
        return -ENOMEM;

    // Fill ICMP header
    icmp_hdr = (struct icmphdr *)packet;
    icmp_hdr->type = ICMP_REPLY;
    icmp_hdr->code = 0;
    icmp_hdr->checksum = 0;
    icmp_hdr->un.echo.id = htons(1234); // Example identifier
    icmp_hdr->un.echo.sequence = htons(1);

    // Add payload
    memcpy(packet + ICMP_HDR_SIZE, PAYLOAD, PAYLOAD_SIZE);

    // Calculate checksum
    icmp_hdr->checksum = checksum((uint16_t *)packet, PACKET_SIZE);

    // Initialize destination address
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_addr.s_addr = in_aton("10.42.2.16"); // Example IP

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


static int __init icmp_module_init(void) {
    pr_info("Loading ICMP kernel module\n");
    return send_icmp_echo_request();
}

static void __exit icmp_module_exit(void) {
    pr_info("Unloading ICMP kernel module\n");
}

module_init(icmp_module_init);
module_exit(icmp_module_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("JackDunfey");
MODULE_DESCRIPTION("ICMP Echo Request Kernel Module");
