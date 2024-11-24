#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/syscalls.h>
#include <linux/dirent.h>
#include <linux/uaccess.h>
#include <linux/fs.h>
#include <linux/dcache.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Jack Dunfey");
MODULE_DESCRIPTION("Kprobe example to hook getdents64");

// Original definition of the target function
asmlinkage int (*original_getdents64)(unsigned int fd, struct linux_dirent64 __user *dirp, unsigned int count);

// Probe pre-handler (called before the actual syscall)
// static int pre_handler(struct kprobe *p, struct pt_regs *regs) {
//     unsigned int fd = (unsigned int)regs->di; // Extract file descriptor from `regs->di`
//     printk(KERN_INFO "Hooked getdents64: fd=%u, process=%s (pid=%d)\n",
//            fd, current->comm, current->pid);
//     return 0;
// }
static int pre_handler(struct kprobe *p, struct pt_regs *regs) {
    unsigned int fd = (unsigned int)regs->di; // Extract file descriptor
    char *path = NULL;
    char buf[PATH_MAX]; // Buffer to store the directory path

    if (fd < 1000) { // Assume valid file descriptors are small integers
        struct file *file = fget(fd); // Retrieve the file structure for the fd
        if (file) {
            path = dentry_path_raw(file->f_path.dentry, buf, sizeof(buf));
            if (!IS_ERR(path)) {
                printk(KERN_INFO "getdents64: fd=%u, process=%s (pid=%d), path=%s\n",
                       fd, current->comm, current->pid, path);
            } else {
                printk(KERN_INFO "getdents64: Could not retrieve path for fd=%u, process=%s (pid=%d)\n",
                       fd, current->comm, current->pid);
            }
            fput(file); // Release the file structure
        } else {
            printk(KERN_INFO "getdents64: fget failed for fd=%u, process=%s (pid=%d)\n",
                   fd, current->comm, current->pid);
        }
    } else {
        printk(KERN_INFO "getdents64: Invalid or corrupted fd=%u, process=%s (pid=%d)\n",
               fd, current->comm, current->pid);
    }

    return 0;
}



// Probe post-handler (called after the actual syscall)
static void post_handler(struct kprobe *p, struct pt_regs *regs, unsigned long flags) {
    printk(KERN_INFO "getdents64 returned: %ld\n", regs_return_value(regs));
}

// Register the kprobe
static struct kprobe kp = {
    .symbol_name = "__x64_sys_getdents64", // Name of the syscall in the kernel
    .pre_handler = pre_handler,
    .post_handler = post_handler,
};

static int __init kprobe_init(void) {
    int ret;

    ret = register_kprobe(&kp);
    if (ret < 0) {
        printk(KERN_ERR "Failed to register kprobe: %d\n", ret);
        return ret;
    }

    printk(KERN_INFO "Kprobe registered for getdents64\n");
    return 0;
}

static void __exit kprobe_exit(void) {
    unregister_kprobe(&kp);
    printk(KERN_INFO "Kprobe unregistered\n");
}

module_init(kprobe_init);
module_exit(kprobe_exit);
