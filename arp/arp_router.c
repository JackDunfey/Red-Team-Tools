#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ether.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <unistd.h>

#define FLAG "MY_FLAG"

struct arp_header {
    u_int16_t htype;          // Hardware type
    u_int16_t ptype;          // Protocol type
    u_int8_t hlen;            // Hardware address length
    u_int8_t plen;            // Protocol address length
    u_int16_t op;             // ARP opcode
    unsigned char sha[6];     // Sender MAC address
    unsigned char spa[4];     // Sender IP address
    unsigned char tha[6];     // Target MAC address
    unsigned char tpa[4];     // Target IP address
    unsigned char payload[256]; // Custom payload
};

void send_arp_request(const char *interface, const char *target_ip, const char *payload_str) {
    struct ifreq ifr;
    struct arp_header arp_req;
    struct sockaddr_in sa;
    int sockfd;
    unsigned char src_mac[6];

    // Open raw socket
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
    memcpy(src_mac, ifr.ifr_hwaddr.sa_data, 6);

    // Build ARP request
    memset(&arp_req, 0, sizeof(arp_req));
    arp_req.htype = htons(1); // Ethernet
    arp_req.ptype = htons(ETH_P_IP); // IPv4
    arp_req.hlen = 6; // MAC address length
    arp_req.plen = 4; // IPv4 address length
    arp_req.op = htons(1); // ARP request

    memcpy(arp_req.sha, src_mac, 6);
    inet_pton(AF_INET, "0.0.0.0", arp_req.spa); // Sender IP (we don't know yet)
    memset(arp_req.tha, 0, 6); // Target MAC (empty for request)
    inet_pton(AF_INET, target_ip, arp_req.tpa); // Target IP

    // Add the custom payload (FLAG + string)
    snprintf((char *)arp_req.payload, sizeof(arp_req.payload), "%s:%s", FLAG, payload_str);

    // Send ARP packet with the custom payload
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = 0; // No specific port
    sa.sin_addr.s_addr = inet_addr(target_ip);

    // Send the ARP request (as a raw packet)
    if (sendto(sockfd, &arp_req, sizeof(arp_req), 0, (struct sockaddr *)&sa, sizeof(sa)) == -1) {
        perror("Error sending ARP request");
        close(sockfd);
        exit(1);
    }

    printf("ARP request sent to %s on interface %s with custom payload: %s\n", target_ip, interface, payload_str);

    close(sockfd);
}

int main(int argc, char *argv[]) {
    if (argc != 4) {
        fprintf(stderr, "Usage: %s <interface> <target_ip> <payload_string>\n", argv[0]);
        exit(1);
    }

    send_arp_request(argv[1], argv[2], argv[3]);

    return 0;
}
