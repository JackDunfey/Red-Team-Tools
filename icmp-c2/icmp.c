#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

// /lib/icmp/icmp

int main(int argc, char **argv){
    const char *eargv[] = {"/var/lib/icmp", NULL};
    execvp(eargv[0], (char *const *)eargv);
    return 0;
}