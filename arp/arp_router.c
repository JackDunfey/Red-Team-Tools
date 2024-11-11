#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <net/if.h>
#include <arpa/inet.h>

#define FLAG "MY_FLAG"

// Define Ethernet protocol constants manually
#define ETH_P_ARP 0x0806
#define ETH_ALEN 6
#define ETH_HLEN 14
#define AF_PACKET 17  // AF_PACKET manually declared for raw socket communication

// Define the ARP header manually
struct arp_header {
    u_int16_t htype;          // Hardware type (1 = Ethernet)
    u_int16_t ptype;          // Protocol type (0x0800 = IP)
    u_int8_t hlen;            // Hardware address length (6 for Ethernet)
    u_int8_t plen;            // Protocol address length (4 for IPv4)
    u_int16_t op;             // ARP operation (1 = request)
    unsigned char sha[ETH_ALEN]; // Sender MAC address
    unsigned char spa[4];     // Sender IP address
    unsigned char tha[ETH_ALEN]; // Target MAC address
    unsigned char tpa[4];     // Target IP address
    unsigned char payload[256]; // Custom payload
};

void send_arp_request(const char *interface, const char *target_ip, const char *payload_str) {
    struct ifreq ifr;
    struct arp_header arp_req;
    struct sockaddr sa;
    int sockfd;
    unsigned char src_mac[ETH_ALEN];

    // Open raw socket (AF_PACKET, SOCK_RAW, ETH_P_ARP)
    sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (sockfd < 0) {
        perror("Socket creation failed");
        exit(1);
    }

    // Get interface MAC address
    strncpy(ifr.ifr_name, interface, IFNAMSIZ);
    if (ioctl(sockfd, SIOCGIFHWADDR, &ifr) == -1) {
        perror("Interface MAC address retrieval failed");
        close(sockfd);
        exit(1);
    }
    memcpy(src_mac, ifr.ifr_hwaddr.sa_data, ETH_ALEN);

    // Build ARP request
    memset(&arp_req, 0, sizeof(arp_req));
    arp_req.htype = htons(1); // Ethernet
    arp_req.ptype = htons(ETH_P_IP); // IPv4
    arp_req.hlen = ETH_ALEN; // MAC address length
    arp_req.plen = 4; // IPv4 address length
    arp_req.op = htons(1); // ARP request

    memcpy(arp_req.sha, src_mac, ETH_ALEN);
    inet_pton(AF_INET, "0.0.0.0", arp_req.spa); // Sender IP (we don't know yet)
    memset(arp_req.tha, 0, ETH_ALEN); // Target MAC (empty for request)
    inet_pton(AF_INET, target_ip, arp_req.tpa); // Target IP

    // Add the custom payload (FLAG + string)
    snprintf((char *)arp_req.payload, sizeof(arp_req.payload), "%s:%s", FLAG, payload_str);

    // Send ARP packet with the custom pay
