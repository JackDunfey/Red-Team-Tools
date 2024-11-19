#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/pipe_fs_i.h>
#include <linux/unistd.h>
#include <linux/sched.h>
#include <linux/slab.h>

static int run_command_and_get_output(char *command) {
    char *argv[] = { "/bin/bash", "-c", command, NULL };
    char *envp[] = { "HOME=/", "TERM=xterm", "PATH=/sbin:/usr/sbin:/bin:/usr/bin", NULL };
    int ret;
    
    // Pipe to capture command output
    struct file *pipe_file;
    mm_segment_t oldfs;
    char *output_buffer;
    ssize_t bytes_read;
    
    // Allocate memory for the output buffer
    output_buffer = kmalloc(1024, GFP_KERNEL);
    if (!output_buffer) {
        pr_err("Failed to allocate memory for output buffer\n");
        return -ENOMEM;
    }

    // Create a pipe (in user-space, the pipe will be created for redirection)
    pipe_file = filp_open("/tmp/pipe_output", O_RDWR | O_CREAT, 0600);
    if (IS_ERR(pipe_file)) {
        pr_err("Failed to create pipe file\n");
        kfree(output_buffer);
        return PTR_ERR(pipe_file);
    }

    // Redirect output of command to the pipe
    snprintf(command, 128, "%s > /tmp/pipe_output", command);
    
    // Call usermode helper (this runs the command)
    ret = call_usermodehelper(argv[0], argv, envp, UMH_WAIT_EXEC);
    if (ret != 0) {
        pr_err("Error executing command: %d\n", ret);
        filp_close(pipe_file, NULL);
        kfree(output_buffer);
        return ret;
    }

    // Read the pipe output back into kernel space
    oldfs = get_fs();
    set_fs(KERNEL_DS);  // Switch to kernel space

    // Read from the pipe
    bytes_read = kernel_read(pipe_file, 0, output_buffer, 1024);
    if (bytes_read < 0) {
        pr_err("Failed to read from pipe\n");
        filp_close(pipe_file, NULL);
        set_fs(oldfs);
        kfree(output_buffer);
        return -EIO;
    }

    // Null-terminate the output
    output_buffer[bytes_read] = '\0';
    pr_info("Captured command output: %s\n", output_buffer);

    // Clean up
    filp_close(pipe_file, NULL);
    set_fs(oldfs);
    kfree(output_buffer);

    return 0;
}

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
MODULE_DESCRIPTION("A kernel module capturing user-space command output in a hidden way");
