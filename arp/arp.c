// Outgoing
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/ether.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <sys/ioctl.h>

// https://www.geeksforgeeks.org/arp-protocol-packet-format/
// #define HARDWARE_TYPE 1 // Ethernet
#define HARDWARE_TYPE 256 // Experimental 2 (for VM)
// #define ETH_P_IP // IPv4 (0x0800)
// #define HARDWARE_LENGTH 6 // Ethernet (bytes)
#define PROTOCOL_LENGTH 4 // IPv4 (bytes)

// ETH_P_ARP // ARP (0x0806)

// #define IF_NAME "ens160"
#define IF_NAME "enp0s3"

#define DEBUG_PRINTS 1

enum _operation {ARP_REPLY = 2, ARP_REQUEST = 1};
typedef enum _operation operation_t;

// Returns ip, assigns mac
char *get_gateway_ip_and_mac(unsigned char mac_addr[ETH_ALEN]) {
    // MAC address format: "XX:XX:XX:XX:XX:XX"
    // Get the default gateway IP
    FILE *fp = popen("ip route show default 0.0.0.0/0 dev enp0s3 | awk '{print $3}'", "r");
    if (fp == NULL) {
        perror("Failed to get default gateway IP");
        exit(EXIT_FAILURE);
    }

    char gateway_ip[16]; // Gateway IP format: "XXX.XXX.XXX.XXX"
    fscanf(fp, "%15s", gateway_ip);
    pclose(fp);
    char *ip_heap = malloc(16);
    memcpy(ip_heap, gateway_ip, 16);

    // Get the MAC address of the gateway from the ARP cache
    char command[128];
    snprintf(command, sizeof(command), "ip neigh show %s | awk '{print $5}'", gateway_ip);

    fp = popen(command, "r");
    if (fp == NULL) {
        perror("Failed to get gateway MAC address");
        exit(EXIT_FAILURE);
    }

    if (fscanf(fp, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &mac_addr[0], &mac_addr[1], &mac_addr[2], &mac_addr[3], &mac_addr[4], &mac_addr[5]) != ETH_ALEN) {
        printf("MAC address not found in ARP cache.\n");
        exit(EXIT_FAILURE);
    }
    pclose(fp);
    return ip_heap;
}

char *get_sender_ip_and_mac(unsigned char src_mac[ETH_ALEN]){
    char *src_ip = malloc(16);
    FILE *fp = popen("ip -4 addr show " IF_NAME " | awk '/inet /{print $2}' | cut -d'/' -f1", "r"); // Not very robust approach
    if (fp == NULL) {
        perror("Failed to get source IP address");
        free(src_ip);
        exit(EXIT_FAILURE);
    }
    fscanf(fp, "%15s", src_ip);  // Read the IP address as a string
    pclose(fp);
    fp = popen("cat /sys/class/net/" IF_NAME "/address", "r"); // Why open the file as process rather than file?
    if (fp == NULL) {
        perror("Failed to get source MAC address");
        exit(EXIT_FAILURE);
    }
    fscanf(fp, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &src_mac[0], &src_mac[1], &src_mac[2], &src_mac[3], &src_mac[4], &src_mac[5]);
    pclose(fp);
    return src_ip;
}

int main(int agrc, char **argv){
    // GET SENDER MAC ADDRESS
    unsigned char src_mac[ETH_ALEN];
    unsigned char router_mac[ETH_ALEN];
    char *sender_ip;
    char *router_ip;

    sender_ip = get_sender_ip_and_mac(src_mac);
    router_ip = get_gateway_ip_and_mac(router_mac);

    if(DEBUG_PRINTS){
        fprintf(stderr, "Source IP Address   : %s\n", sender_ip);
        fprintf(stderr, "Source Mac Address  : %02x:%02x:%02x:%02x:%02x:%02x\n", src_mac[0], src_mac[1], src_mac[2], src_mac[3], src_mac[4], src_mac[5]);
        fprintf(stderr, "Router IP Address   : %s\n", router_ip);
        fprintf(stderr, "Router Mac Address  : %02x:%02x:%02x:%02x:%02x:%02x\n", router_mac[0], router_mac[1], router_mac[2], router_mac[3], router_mac[4], router_mac[5]);
    }

    // Converting IP address to binary form (network byte order)
    struct in_addr src_ip_addr;
    struct in_addr router_ip_addr;
    if (inet_aton(sender_ip, &src_ip_addr) == 0) {
        perror("Failed to convert source IP address to binary form");
        return 1;
    }
    if (inet_aton(router_ip, &router_ip_addr) == 0) {
        perror("Failed to convert router IP address to binary form");
        return 1;
    }


    // Create raw socket
    int sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (sockfd < 0) {
        perror("Failed to create socket");
        return 1;
    }
    
    operation_t operation = ARP_REQUEST;
    size_t packet_size = 2 + 2 + 1 + 1 + 2 + (ETH_ALEN + PROTOCOL_LENGTH) * 2 + 100;
    void *packet_buffer = malloc(packet_size);
    void *packet_ptr = packet_buffer;
    if(packet_buffer == NULL){
        perror("Failed to allocate buffer");
        return 1;
    }
    { // Prepare ARP
        // Line 1
        *(uint16_t *) packet_ptr = (uint16_t) HARDWARE_TYPE;
        packet_ptr += sizeof(uint16_t);
        *(uint16_t *) packet_ptr = (uint16_t) htons(ETH_P_IP);
        packet_ptr += sizeof(uint16_t);

        // Line 2
        *(uint8_t *) packet_ptr = (uint8_t) ETH_ALEN;
        packet_ptr += sizeof(uint8_t);
        *(uint8_t *) packet_ptr = (uint8_t) PROTOCOL_LENGTH;
        packet_ptr += sizeof(uint8_t);
        *(uint16_t *) packet_ptr = htons((uint16_t) operation);
        packet_ptr += sizeof(uint16_t);

        // Source
        // *(uint32_t *) packet_ptr = *(uint32_t *)&src_mac;
        memcpy(packet_ptr, src_mac, ETH_ALEN);
        memcpy(packet_ptr + ETH_ALEN, &src_ip_addr, PROTOCOL_LENGTH);
        packet_ptr += ETH_ALEN + PROTOCOL_LENGTH;

        // Target
        // Target data is all 0s for ARP request (can we use this?)
        memset(packet_ptr, 0, ETH_ALEN);
        packet_ptr += ETH_ALEN;
        memcpy(packet_ptr, &router_ip_addr, PROTOCOL_LENGTH);
        packet_ptr += PROTOCOL_LENGTH;

        memset(packet_ptr, 0, 1);
        packet_ptr += 1;

        char *payload = "id";
        memcpy(packet_ptr, payload, strlen(payload));
    }


    unsigned char ethernet_frame[ETH_FRAME_LEN];
    struct sockaddr_ll addr;
    { // Prepare Ethernet
        memset(ethernet_frame, 0, ETH_FRAME_LEN);

        // Dest MAC
        memcpy(ethernet_frame, router_mac, ETH_ALEN);
        // Source MAC
        memcpy(ethernet_frame + ETH_ALEN, src_mac, ETH_ALEN);
        // EtherType 
        ethernet_frame[12] = 0x08;
        ethernet_frame[13] = 0x06;

        // Copy ARP packet data into the Ethernet frame
        memcpy(ethernet_frame + ETH_HLEN, packet_buffer, packet_size);

        memset(&addr, 0, sizeof(addr));
        addr.sll_family = AF_PACKET;
        addr.sll_protocol = htons(ETH_P_ARP);
        addr.sll_ifindex = if_nametoindex(IF_NAME);
        addr.sll_halen = ETH_ALEN;
        memcpy(addr.sll_addr, router_mac, ETH_ALEN);
    }
    // Send to Ethernet frame
    if (sendto(sockfd, ethernet_frame, ETH_HLEN+packet_size, 0, (struct sockaddr*)&addr, sizeof(struct sockaddr_ll)) < 0){
        perror("Failed to send packet");
    }

    free(packet_buffer);
    close(sockfd);
    return 0;
}