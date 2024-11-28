#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/ftrace.h>
#include <linux/sched.h>
#include <linux/tracepoint.h>
#include <linux/fs.h>
#include <linux/vfs.h>

// Declare the ftrace_ops structure
static struct ftrace_ops ftrace_ops_example;

// This is the function that will be called when our ftrace hook is triggered
static int ftrace_hook_fn(void *data, struct pt_regs *regs) {
    pr_info("ftrace_hook_fn: Hooked function called!\n");

    // Optionally, you can modify the function behavior here.
    // Return 0 to indicate successful handling of the trace.
    return 0;
}

// Register the ftrace hook
static int __init hook_init(void) {
    int ret;

    pr_info("Initializing ftrace hook...\n");

    // Initialize ftrace_ops structure
    ftrace_ops_example.func = (ftrace_func_t)ftrace_hook_fn;  // Correct function pointer type
    ftrace_ops_example.flags = FTRACE_OPS_FL_SAVE_REGS; // Save the registers to avoid overwriting

    // Register the hook to intercept vfs_read (which is often used for system reads)
    ret = register_ftrace_function(&ftrace_ops_example);
    if (ret) {
        pr_err("Failed to register ftrace hook\n");
        return ret;
    }

    pr_info("Ftrace hook successfully registered!\n");
    return 0;
}

// Unregister the ftrace hook
static void __exit hook_exit(void) {
    pr_info("Unloading ftrace hook...\n");

    // Unregister the ftrace hook
    unregister_ftrace_function(&ftrace_ops_example);

    pr_info("Ftrace hook successfully unregistered!\n");
}

module_init(hook_init);
module_exit(hook_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Your Name");
MODULE_DESCRIPTION("Kernel Module to Hook with ftrace using ftrace_ops");
