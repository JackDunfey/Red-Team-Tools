#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char *argv[]) {
    if (argc != 7) {
        fprintf(stderr, "Usage: %s <src_hw> <src_proto> <dst_hw> <dst_proto> <payload_len> <payload>\n", argv[0]);
        return 1;
    }

    char *src_hw = argv[1];
    char *src_proto = argv[2];
    char *dst_hw = argv[3];
    char *dst_proto = argv[4];
    int payload_len = atoi(argv[5]);
    char *payload = argv[6];

    // Output the received ARP information
    printf("Received ARP request:\n");
    printf("Source MAC: %s\n", src_hw);
    printf("Source IP: %s\n", src_proto);
    printf("Destination MAC: %s\n", dst_hw);
    printf("Destination IP: %s\n", dst_proto);
    printf("Payload Length: %d\n", payload_len);
    printf("Payload: %s\n", payload);

    // You can add custom processing here if needed

    return 0;
}
