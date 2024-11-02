#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/if_arp.h>
#include <linux/etherdevice.h>
#include <linux/fs.h>
#include <linux/uaccess.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Your Name");
MODULE_DESCRIPTION("Kernel module to forward ARP requests to user-space via pipes");

#define DEVICE_NAME "arp_device"
#define BUFFER_SIZE 2048

static int major_number;        // Store the device's major number
static char buffer[BUFFER_SIZE]; // Buffer to hold ARP data
static int buffer_len = 0;       // Length of data in the buffer
static int open_count = 0;       // Count of how many times the device has been opened

// Function to handle ARP requests
static unsigned int arp_hook_func(void *priv,
                                   struct sk_buff *skb,
                                   const struct nf_hook_state *state)
{
    struct ethhdr *eth = eth_hdr(skb);

    if (ntohs(eth->h_proto) == ETH_P_ARP) {
        struct arphdr *arp = (struct arphdr *)(skb->data + sizeof(struct ethhdr));
        
        printk(KERN_INFO "ARP hook function triggered.\n");

        // Check if the packet is an ARP request
        if (ntohs(arp->ar_op) == ARPOP_REQUEST) {
            printk(KERN_INFO "ARP request detected. Packet length: %d\n", skb->len);

            // Copy ARP request data into the buffer
            if (buffer_len + skb->len <= BUFFER_SIZE) {
                memcpy(buffer + buffer_len, skb->data, skb->len);
                buffer_len += skb->len;
                buffer[buffer_len] = '\0'; // Null-terminate for safety
                printk(KERN_INFO "ARP data added to buffer. Current buffer length: %d\n", buffer_len);
            } else {
                printk(KERN_WARNING "Buffer overflow prevented. Buffer length: %d, Packet size: %d\n", buffer_len, skb->len);
            }
        }
    }

    return NF_ACCEPT; // Accept the ARP request
}

// Device open function
static int device_open(struct inode *inode, struct file *file)
{
    if (open_count) {
        printk(KERN_WARNING "Device already open.\n");
        return -EBUSY;
    }
    open_count++;
    printk(KERN_INFO "Device opened. Open count: %d\n", open_count);
    return 0;
}

// Device read function
static ssize_t device_read(struct file *file, char __user *buf, size_t count, loff_t *offset)
{
    if (buffer_len == 0) {
        printk(KERN_INFO "No data to read from buffer.\n");
        return 0; // No data to read
    }

    printk(KERN_INFO "Reading %d bytes from buffer.\n", buffer_len);

    // Copy data to user-space buffer
    if (copy_to_user(buf, buffer, buffer_len)) {
        printk(KERN_WARNING "Error copying data to user space.\n");
        return -EFAULT;
    }

    ssize_t bytes_read = buffer_len; // Number of bytes read
    buffer_len = 0; // Reset buffer length
    printk(KERN_INFO "Data read successfully. Bytes read: %zd\n", bytes_read);
    return bytes_read;
}

// Device release function
static int device_release(struct inode *inode, struct file *file)
{
    open_count--;
    printk(KERN_INFO "Device released. Open count: %d\n", open_count);
    return 0;
}

// File operations structure
static struct file_operations fops = {
    .open = device_open,
    .read = device_read,
    .release = device_release,
};

// Module initialization
static int __init arp_forwarder_init(void)
{
    printk(KERN_INFO "Initializing ARP forwarder module.\n");

    // Register the character device
    major_number = register_chrdev(0, DEVICE_NAME, &fops);
    if (major_number < 0) {
        printk(KERN_ALERT "Failed to register character device: %d\n", major_number);
        return major_number;
    }

    printk(KERN_INFO "Registered character device with major number %d\n", major_number);

    // Setup Netfilter hook
    nfho.hook = arp_hook_func;
    nfho.hooknum = NF_INET_PRE_ROUTING;
    nfho.pf = NFPROTO_INET;
    nfho.priority = NF_IP_PRI_FIRST;

    nf_register_net_hook(&init_net, &nfho);
    printk(KERN_INFO "ARP forwarder module loaded successfully.\n");
    return 0;
}

// Module cleanup
static void __exit arp_forwarder_exit(void)
{
    nf_unregister_net_hook(&init_net, &nfho); // Unregister the hook
    unregister_chrdev(major_number, DEVICE_NAME); // Unregister the character device
    printk(KERN_INFO "ARP forwarder module unloaded.\n");
}

module_init(arp_forwarder_init);
module_exit(arp_forwarder_exit);
