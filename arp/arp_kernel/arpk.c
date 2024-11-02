#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter/x_tables.h>
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

static struct nf_hook_ops nfho; // Netfilter hook option struct
static char buffer[BUFFER_SIZE]; // Buffer for ARP data
static int buffer_len = 0; // Length of data in buffer
static int open_count = 0; // Count of how many times the device has been opened

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
            // Copy ARP request data into the buffer
            if (buffer_len + skb->len <= BUFFER_SIZE) {
                memcpy(buffer + buffer_len, skb->data, skb->len);
                buffer_len += skb->len;
                buffer[buffer_len] = '\0'; // Null-terminate for safety
                printk(KERN_INFO "Captured ARP request: %s\n", buffer);
            } else {
                printk(KERN_WARNING "Buffer overflow prevented!\n");
            }
        }
    }

    return NF_ACCEPT; // Accept the ARP request
}

// Device open function
static int device_open(struct inode *inode, struct file *file)
{
    if (open_count) {
        return -EBUSY; // Device is already open
    }
    open_count++;
    return 0; // Success
}

// Device read function
static ssize_t device_read(struct file *file, char __user *buf, size_t count, loff_t *offset)
{
    if (buffer_len == 0) {
        return 0; // No data to read
    }

    if (copy_to_user(buf, buffer, buffer_len)) {
        return -EFAULT; // Error copying data to user
    }

    ssize_t bytes_read = buffer_len; // Number of bytes read
    buffer_len = 0; // Reset buffer length
    return bytes_read; // Return number of bytes read
}

// Device release function
static int device_release(struct inode *inode, struct file *file)
{
    open_count--; // Decrement open count
    return 0; // Success
}

// File operations structure
static struct file_operations fops = {
    .owner = THIS_MODULE,
    .open = device_open,
    .read = device_read,
    .release = device_release,
};

// Module initialization
static int __init arp_forwarder_init(void)
{
    // Register the character device
    int result = register_chrdev(0, DEVICE_NAME, &fops);
    if (result < 0) {
        printk(KERN_ALERT "Failed to register character device: %d\n", result);
        return result;
    }

    // Setup Netfilter hook
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
    unregister_chrdev(0, DEVICE_NAME); // Unregister the character device
    printk(KERN_INFO "ARP forwarder module unloaded.\n");
}

module_init(arp_forwarder_init);  // Register module initialization function
module_exit(arp_forwarder_exit);   // Register module cleanup function
