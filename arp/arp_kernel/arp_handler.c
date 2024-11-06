#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>

#define PACKET_LEN 65535
#define IF_NAME "enp0s3" // FIXME: make this automatic

void send_arp_reply(const char *iface, const char *src_mac_str, const char *src_ip_str,
                    const char *dst_mac_str, const char *dst_ip_str, const char *payload) {
    int sockfd;
    unsigned char packet[PACKET_LEN];
    struct sockaddr_ll sa;
    unsigned char src_mac[MAC_LEN], dst_mac[MAC_LEN];
    struct in_addr src_ip, dst_ip;

    // Create raw socket
    if ((sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP))) < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    // Retrieve MAC and IP of the interface
    if (get_mac_address(iface, src_mac) < 0 || get_ip_address(iface, &src_ip) < 0) {
        fprintf(stderr, "Failed to get MAC or IP address of interface %s\n", iface);
        close(sockfd);
        exit(EXIT_FAILURE);
    }
    inet_aton(src_ip_str, &src_ip);
    inet_aton(dst_ip_str, &dst_ip);

    // Convert destination MAC address string to bytes
    sscanf(dst_mac_str, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
           &dst_mac[0], &dst_mac[1], &dst_mac[2],
           &dst_mac[3], &dst_mac[4], &dst_mac[5]);

    // Fill Ethernet header
    memcpy(packet, dst_mac, MAC_LEN);                // Destination MAC
    memcpy(packet + MAC_LEN, src_mac, MAC_LEN);      // Source MAC
    packet[12] = ETH_TYPE_ARP >> 8;
    packet[13] = ETH_TYPE_ARP & 0xff;

    // Fill ARP header for a reply
    unsigned char *arp_header = packet + 14;
    arp_header[0] = 0x00;                            // Hardware type (Ethernet)
    arp_header[1] = 0x01;
    arp_header[2] = 0x08;                            // Protocol type (IP)
    arp_header[3] = 0x00;
    arp_header[4] = MAC_LEN;                         // Hardware size
    arp_header[5] = IP_LEN;                          // Protocol size
    arp_header[6] = ARP_REPLY_OPCODE >> 8;           // Opcode (ARP Reply)
    arp_header[7] = ARP_REPLY_OPCODE & 0xff;

    // ARP Payload for reply
    memcpy(arp_header + 8, src_mac, MAC_LEN);        // Sender MAC address
    memcpy(arp_header + 14, &src_ip, IP_LEN);        // Sender IP address
    memcpy(arp_header + 18, dst_mac, MAC_LEN);       // Target MAC address
    memcpy(arp_header + 24, &dst_ip, IP_LEN);        // Target IP address

    // Append custom payload if any
    size_t arp_packet_len = sizeof(struct ethhdr) + 28 + strlen(payload);
    memcpy(packet + sizeof(struct ethhdr) + 28, payload, strlen(payload));

    // Set up socket address structure
    memset(&sa, 0, sizeof(sa));
    sa.sll_ifindex = if_nametoindex(iface);
    sa.sll_halen = MAC_LEN;
    memcpy(sa.sll_addr, dst_mac, MAC_LEN);

    // Send the ARP reply packet
    if (sendto(sockfd, packet, arp_packet_len, 0, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        perror("sendto");
    } else {
        printf("ARP reply sent to %s\n", dst_ip_str);
    }

    close(sockfd);
}

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

    // Send ARP reply
    send_arp_reply(IF_NAME, src_hw, src_proto, dst_hw, dst_proto, payload);

    // Log to file
    FILE *fp = fopen("/tmp/filename", "a+");
    fprintf(fp, "ARP reply sent!\n\tCommand: %s\n", payload);
    fclose(fp);

    return 0;
}
