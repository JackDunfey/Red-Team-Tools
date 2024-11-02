#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#define DEVICE "/dev/arp_device"
#define BUFFER_SIZE 2048

int main() {
    printf("Starting ARP handler program.\n");

    int fd = open(DEVICE, O_RDONLY);
    if (fd < 0) {
        perror("Failed to open device");
        return EXIT_FAILURE;
    }
    printf("Opened device: %s\n", DEVICE);

    char buffer[BUFFER_SIZE];
    ssize_t bytes_read;

    while (1) {
        printf("Attempting to read from device...\n");
        
        // Read data from the device
        bytes_read = read(fd, buffer, sizeof(buffer) - 1);
        if (bytes_read > 0) {
            buffer[bytes_read] = '\0'; // Null-terminate the string
            printf("Received ARP request: %s\n", buffer);
            printf("Bytes read: %zd\n", bytes_read);
        } else if (bytes_read < 0) {
            perror("Failed to read from device");
            break;
        } else {
            printf("No data available. Retrying...\n");
        }

        // Sleep to avoid busy waiting
        usleep(100000); // 100 milliseconds
    }

    close(fd);
    printf("ARP handler program terminated.\n");
    return EXIT_SUCCESS;
}
