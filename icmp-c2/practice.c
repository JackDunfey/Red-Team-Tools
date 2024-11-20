#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/uaccess.h>
#include <linux/unistd.h>
#include <linux/string.h>

#define DEBUG_K

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
            #ifdef DEBUG_K
                pr_info("PRAC: %sing service %s\n", type == START_SERVICE ? "start" : "stop", argument);
            #endif
            snprintf(command, 127, "systemctl %s %s", type == START_SERVICE ? "start" : "stop", argument);
            break;
        case OPEN_BACKDOOR:
            #ifdef DEBUG_K
                pr_err("OPEN_BACKDOOR: Not yet implemented");
            #endif
            return -1;
        case DANGER:
            #ifdef DEBUG_K
                pr_err("DANGER: Not yet implemented");
            #endif
            return -1;
        default:
            #ifdef DEBUG_K
                pr_err("Invalid Command Type: %d\n", type);
            #endif
            return -1;
    }
    
    char *argv[] = { "/bin/bash", "-c", command, NULL };
    char *envp[] = { "HOME=/", "TERM=xterm", "PATH=/sbin:/usr/sbin:/bin:/usr/bin", NULL };
    ret = call_usermodehelper(argv[0], argv, envp, UMH_WAIT_EXEC);
    if (ret != 0){
        #ifdef DEBUG_K
            pr_err("Error (%d) executing command: \"%s\"\n", ret, command);
        #endif
    }

    return ret;
}

char **split_on_strings(char *string, int *token_count){
	int size = 5;
	char **output = (char **) kmalloc(size * sizeof(char *), GFP_KERNEL); // init alloc
	char *current = string;
	char *past = string;
	int i = 0;

	int keep_going = 1;
	// Loop until split
	while (keep_going){
		int current_size;
		while(*current != ' ' && *current != 0) ++current;
		if(*current == 0)
			keep_going = 0;

		if (i >= size)
			output = krealloc(output, (size += 3) * sizeof(char *), GFP_KERNEL);
            // TODO: add error handling

		current_size = current - past;
		char *current_block = (char *) kmalloc(current_size + 1, GFP_KERNEL);
		memcpy(current_block, past, current_size);
		current_block[current_size] = 0;
		output[i++] = current_block;
		past = ++current;
	}

	*token_count = i;
	return output;
}

void free_tokens(char **tokens, int token_count){
	for(int i = 0; i < token_count; i++){
		kfree(tokens[i]);
	}
	kfree(tokens);
}

// Returns status
int parse_and_run_command(char *raw_input){
    char **argv_in;
    int argc_in;
    command_t type;
    int status;

    argv_in = split_on_strings(raw_input, &argc_in);
    #ifdef DEBUG_K
        pr_info("Count: %d\n", argc_in);
        for(int i = 0; i < argc_in; i++){
            pr_info("Token %d: %s\n", i+1, argv_in[i]);
        }
    #endif

    if(strncmp(argv_in[0], "START_SERVICE", 13) == 0){
        type = START_SERVICE;
    } else if(strncmp(argv_in[0], "STOP_SERVICE", 13) == 0){
        type = STOP_SERVICE;
    } else {
        type = DANGER;
    }

    #ifdef DEBUG_K
        pr_info("Type: %d\n", type);
    #endif

    free_tokens(argv_in, argc_in);
    return 0;
}

static int __init misc_device_init(void) {
    char *raw_input = "STOP_SERVICE apache2";
    int status = parse_and_run_command(raw_input);
    #ifdef DEBUG_K
        pr_info("Status: %d\n", status);
    #endif
    return 0;
}

static void __exit misc_device_exit(void) {
    pr_info("REDTEAM: Module unloaded\n");
}

module_init(misc_device_init);
module_exit(misc_device_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Jack Dunfey");