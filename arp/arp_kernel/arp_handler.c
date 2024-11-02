#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>

#define DEVICE "/dev/arp_device"

int main() {
    int fd = open(DEVICE, O_RDONLY);
    if (fd < 0) {
        perror("Failed to open device");
        return EXIT_FAILURE;
    }

    char buffer[2048];
    ssize_t bytes_read;

    while (1) {
        bytes_read = read(fd, buffer, sizeof(buffer) - 1);
        if (bytes_read > 0) {
            buffer[bytes_read] = '\0'; // Null-terminate the string
            printf("Received ARP request: %s\n", buffer);
        } else if (bytes_read < 0) {
            perror("Failed to read from device");
            break;
        }
        // Sleep for a while to avoid busy waiting
        usleep(100000); // Sleep for 100 milliseconds
    }

    close(fd);
    return EXIT_SUCCESS;
}
