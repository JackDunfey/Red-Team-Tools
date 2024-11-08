#include <stdio.h>
#include <stdlib.h>

int main() {
    FILE *fp = fopen("/sys/class/net/enp0s3/address", "r");
    if (fp == NULL) {
        perror("Unable to open file");
        return 1;
    }

    // Buffer to store the MAC address string from the file
    char mac_str[18];
    if (fgets(mac_str, sizeof(mac_str), fp) == NULL) {
        perror("Failed to read MAC address");
        fclose(fp);
        return 1;
    }
    fclose(fp);

    // Array to store the MAC address in binary format
    unsigned char mac[6];
    if (sscanf(mac_str, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
               &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]) != 6) {
        fprintf(stderr, "Failed to parse MAC address\n");
        return 1;
    }

    // Print the MAC address in binary format for verification
    printf("MAC address in binary: %02x:%02x:%02x:%02x:%02x:%02x\n",
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

    return 0;
}
