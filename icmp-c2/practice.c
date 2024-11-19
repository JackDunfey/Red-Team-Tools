#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/uaccess.h>
#include <linux/unistd.h>
#include <linux/string.h>

// Time to implement a custom command language in the linux kernel :)
typedef enum COMMANDS {
    START_SERVICE = 0,
    STOP_SERVICE  = 1,
    OPEN_BACKDOOR = 2,
    DANGER        = 4
} command_t;

static int execute_and_get_status(command_t type, char *argument){
    char *argv[] = { "/bin/bash", "-c", command, NULL };
    char *envp[] = { "HOME=/", "TERM=xterm", "PATH=/sbin:/usr/sbin:/bin:/usr/bin", NULL };

    char command[128] = {0};
    int ret;
    
    switch(type){
        case START_SERVICE:
        case STOP_SERVICE:
            snprintf(command, 127, "systemctl %s %s", type == START_SERVICE ? "start" : "stop", argument);
            break
    }

    
    ret = call_usermodehelper(argv[0], argv, envp, UMH_WAIT_EXEC);
    if (ret != 0){
        pr_err("Error (%d) executing command: \"%s\"\n", ret, command);
    }
}

static int __init misc_device_init(void) {
    command_t type = STOP_SERVICE;
    char *arg_s = "apache2";
    int status = execute_and_get_status(type, arg_s);
    pr_info("Status: %d\n", status);
    return 0;
}

static void __exit misc_device_exit(void) {
    misc_deregister(&misc_dev);
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
