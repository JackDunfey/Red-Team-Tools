#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/pipe_fs_i.h>
#include <linux/unistd.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/vfs.h>  // For vfs_unlink()

// static int run_command_and_get_output(char *command) {
//     char *argv[] = { "/bin/bash", "2>&1", "-c", command, NULL };
//     char *envp[] = { "HOME=/", "TERM=xterm", "PATH=/sbin:/usr/sbin:/bin:/usr/bin", NULL };
//     return 0;
// }

#include <linux/module.h>
#include <linux/miscdevice.h>
#include <linux/fs.h>
#include <linux/uaccess.h>

// Buffer for storing data between user space and kernel space
#define BUFFER_SIZE 1024
static char buffer[BUFFER_SIZE];
static int buffer_index = 0;

// File operations struct
static ssize_t device_read(struct file *file, char __user *user_buffer, size_t len, loff_t *offset) {
    // Check if user buffer size exceeds buffer index
    if (*offset >= buffer_index)
        return 0;

    // Read data from kernel space buffer into user space
    if (copy_to_user(user_buffer, buffer, buffer_index - *offset)) {
        return -EFAULT; // Error in copying data to user space
    }

    *offset += buffer_index;
    return buffer_index;
}

static ssize_t device_write(struct file *file, const char __user *user_buffer, size_t len, loff_t *offset) {
    // Check if data exceeds buffer size
    if (len > BUFFER_SIZE)
        return -E2BIG;

    // Write data from user space to kernel space buffer
    if (copy_from_user(buffer, user_buffer, len)) {
        return -EFAULT; // Error in copying data from user space
    }

    buffer_index = len;
    return len;
}

// File operations struct
static const struct file_operations fops = {
    .owner = THIS_MODULE,
    .read = device_read,
    .write = device_write,
};

// Misc device structure
static struct miscdevice misc_dev = {
    .minor = MISC_DYNAMIC_MINOR,
    .name = "misc_char_device",
    .fops = &fops,
};

static int __init misc_device_init(void) {
    int ret = misc_register(&misc_dev);
    if (ret) {
        pr_err("Failed to register misc device: %d\n", ret);
        return ret;
    }
    pr_info("Misc char device registered under /dev/misc_char_device\n");
    return 0;
}

static void __exit misc_device_exit(void) {
    misc_deregister(&misc_dev);
    pr_info("Misc char device unregistered from /dev\n");
}

module_init(misc_device_init);
module_exit(misc_device_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Your Name");
MODULE_DESCRIPTION("A simple Misc character device kernel module for IPC");


static int __init my_module_init(void) {
    pr_info("Kernel module loaded.\n");
    return run_command_and_get_output("echo Hello from hidden kernel method!");
}

static void __exit my_module_exit(void) {
    pr_info("Kernel module unloaded.\n");
}

module_init(my_module_init);
module_exit(my_module_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Your Name");
MODULE_DESCRIPTION("A kernel module capturing user-space command output and deleting file afterwards");
