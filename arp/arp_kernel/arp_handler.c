#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char *argv[]) {
    if (argc != 6) {
        fprintf(stderr, "Usage: %s <src_hw> <src_proto> <dst_hw> <dst_proto> <payload>\n", argv[0]);
        return 1;
    }

    char *src_hw = argv[1];
    char *src_proto = argv[2];
    char *dst_hw = argv[3];
    char *dst_proto = argv[4];
    char *payload = argv[5];

    // Output the received ARP information
    printf("Received ARP request:\n");
    printf("Source MAC: %s\n", src_hw);
    printf("Source IP: %s\n", src_proto);
    printf("Destination MAC: %s\n", dst_hw);
    printf("Destination IP: %s\n", dst_proto);
    printf("Payload Length: %ld\n", strlen(payload));
    printf("Payload: %s\n", payload);

    // You can add custom processing here if needed

    return 0;
}
