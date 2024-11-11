#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <net/ethernet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/arp.h>

#define FLAG "MY_FLAG"

// Define ARP request operation code
#define ARP_REQUEST 1

// Define Ethernet header structure
struct eth_header {
    unsigned char dest_mac[6];
    unsigned char src_mac[6];
    unsigned short ethertype;
};

// Define ARP header structure
struct arp_header {
    unsigned short hw_type;
    unsigned short proto_type;
    unsigned char hw_len;
    unsigned char proto_len;
    unsigned short opcode;
    unsigned char sender_mac[6];
    unsigned char sender_ip[4];
    unsigned char target_mac[6];
    unsigned char target_ip[4];
};

// Send ARP request
void send_arp_request(const char *interface, const char *target_ip, const char *message) {
    int sockfd;
    struct sockaddr_ll sa;
    struct ifreq ifr;
    unsigned char buffer[42 + strlen(message)];
    struct eth_header *eth_header = (struct eth_header *)buffer;
    struct arp_header *arp_header = (struct arp_header *)(buffer + 14);

    // Open raw socket
    sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (sockfd == -1) {
        perror("Socket creation failed");
        exit(1);
    }

    // Get MAC address of the interface
    strncpy(ifr.ifr_name, interface, IFNAMSIZ);
    if (ioctl(sockfd, SIOCGIFHWADDR, &ifr) == -1) {
        perror("IOCTL error");
        close(sockfd);
        exit(1);
    }

    unsigned char *src_mac = (unsigned char *)ifr.ifr_hwaddr.sa_data;

    // Set up Ethernet header
    memset(eth_header->dest_mac, 0xFF, 6);  // Broadcast MAC
    memcpy(eth_header->src_mac, src_mac, 6);
    eth_header->ethertype = htons(ETH_P_ARP);

    // Set up ARP header
    arp_header->hw_type = htons(ARPHRD_ETHER);  // Ethernet
    arp_header->proto_type = htons(ETH_P_IP);   // IPv4
    arp_header->hw_len = 6;                     // MAC length
    arp_header->proto_len = 4;                  // IP length
    arp_header->opcode = htons(ARP_REQUEST);    // ARP Request

    // Set sender MAC and IP (we don't know the sender's IP)
    memcpy(arp_header->sender_mac, src_mac, 6);
    inet_pton(AF_INET, "0.0.0.0", arp_header->sender_ip);  // 0.0.0.0 as placeholder for sender IP

    // Set the target IP address
    inet_pton(AF_INET, target_ip, arp_header->target_ip);

    // Target MAC set to all zeros (ARP request)
    memset(arp_header->target_mac, 0x00, 6);

    // Append the FLAG and message as payload after the ARP header
    strcpy((char *)(buffer + 42), FLAG);
    strcat((char *)(buffer + 42), message);

    // Prepare sockaddr_ll structure
    memset(&sa, 0, sizeof(sa));
    sa.sll_protocol = htons(ETH_P_ARP);
    sa.sll_ifindex = if_nametoindex(interface);

    // Send the ARP request
    if (sendto(sockfd, buffer, 42 + strlen(message), 0, (struct sockaddr *)&sa, sizeof(sa)) == -1) {
        perror("Send failed");
        close(sockfd);
        exit(1);
    }

    printf("ARP request sent to %s with FLAG: %s and message: %s\n", target_ip, FLAG, message);

    close(sockfd);
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <interface> <target_ip>\n", argv[0]);
        exit(1);
    }

    const char *interface = argv[1];
    const char *target_ip = argv[2];
    const char *message = argv[3];

    // Send ARP request
    send_arp_request(interface, target_ip, message);

    return 0;
}
