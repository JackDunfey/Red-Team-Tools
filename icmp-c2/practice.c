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
    char command[128] = {0};
    int ret;

    
    switch(type){
        case START_SERVICE:
        case STOP_SERVICE:
            pr_info("PRAC: %sing service %s\n", type == START_SERVICE ? "start" : "stop", argument);
            snprintf(command, 127, "systemctl %s %s", type == START_SERVICE ? "start" : "stop", argument);
            break;
        case OPEN_BACKDOOR:
            pr_err("OPEN_BACKDOOR: Not yet implemented");
            return -1;
        case DANGER:
            pr_err("DANGER: Not yet implemented");
            return -1;
        default:
            pr_err("Invalid Command Type: %d\n", type);
            return -1;
    }
    
    char *argv[] = { "/bin/bash", "-c", command, NULL };
    char *envp[] = { "HOME=/", "TERM=xterm", "PATH=/sbin:/usr/sbin:/bin:/usr/bin", NULL };
    ret = call_usermodehelper(argv[0], argv, envp, UMH_WAIT_EXEC);
    if (ret != 0){
        pr_err("Error (%d) executing command: \"%s\"\n", ret, command);
    }

    return ret;
}

static int __init misc_device_init(void) {
    command_t type = STOP_SERVICE;
    char *arg_s = "apache2";
    int status = execute_and_get_status(type, arg_s);
    pr_info("Status: %d\n", status);
    return 0;
}

static void __exit misc_device_exit(void) {
    pr_info("Module unloaded\n");
}

module_init(misc_device_init);
module_exit(misc_device_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Jack Dunfey");