#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/if_arp.h>
#include <linux/if_packet.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/ethernet.h>

#define BUFFER_SIZE 2048

int main() {
    int sockfd;
    struct sockaddr_in addr;
    char buffer[BUFFER_SIZE];

    // Create a raw socket to receive ARP requests
    sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (sockfd < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    while (1) {
        // Receive packets
        ssize_t len = recv(sockfd, buffer, BUFFER_SIZE, 0);
        if (len < 0) {
            perror("recv");
            close(sockfd);
            exit(EXIT_FAILURE);
        }

        struct ether_arp *arp = (struct ether_arp *)(buffer + sizeof(struct ether_header));
        
        // Check if the packet is an ARP request
        if (ntohs(arp->ea_hdr.ar_op) == ARPOP_REQUEST) {
            char sender_ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, arp->arp_spa, sender_ip, sizeof(sender_ip));
            printf("Received ARP request from %s\n", sender_ip);
        }
    }

    close(sockfd);
    return 0;
}
