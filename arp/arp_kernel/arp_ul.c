#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <sys/types.h>
#include <sys/stat.h>

#define DEVICE_NAME "/dev/arpk"

int main()
{
    int fd;
    char buffer[256];

    fd = open(DEVICE_NAME, O_RDONLY);
    if (fd < 0) {
        perror("Failed to open device");
        return 1;
    }

    while (1) {
        // Read ARP request notifications from kernel module
        ssize_t bytesRead = read(fd, buffer, sizeof(buffer) - 1);
        if (bytesRead > 0) {
            buffer[bytesRead] = '\0'; // Null terminate the string
            printf("Received: %s\n", buffer);
        } else if (bytesRead < 0) {
            perror("Failed to read from device");
            break;
        }
    }

    close(fd);
    return 0;
}
