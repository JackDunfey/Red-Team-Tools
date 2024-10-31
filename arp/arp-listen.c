#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>

#define BUF_SIZE 65536

// Function to print the MAC address
void print_mac_address(unsigned char *mac) {
    printf("%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void dumpHex(const void* data, size_t size) {
	char ascii[17];
	size_t i, j;
	ascii[16] = '\0';
	for (i = 0; i < size; ++i) {
		printf("%02X ", ((unsigned char*)data)[i]);
		if (((unsigned char*)data)[i] >= ' ' && ((unsigned char*)data)[i] <= '~') {
			ascii[i % 16] = ((unsigned char*)data)[i];
		} else {
			ascii[i % 16] = '.';
		}
		if ((i+1) % 8 == 0 || i+1 == size) {
			printf(" ");
			if ((i+1) % 16 == 0) {
				printf("|  %s \n", ascii);
			} else if (i+1 == size) {
				ascii[(i+1) % 16] = '\0';
				if ((i+1) % 16 <= 8) {
					printf(" ");
				}
				for (j = (i+1) % 16; j < 16; ++j) {
					printf("   ");
				}
				printf("|  %s \n", ascii);
			}
		}
	}
}

// Main packet sniffer function
int main() {
    int sockfd;
    unsigned char buffer[BUF_SIZE];
    struct sockaddr saddr;
    struct ethhdr *eth_header;
    socklen_t saddr_len = sizeof(saddr);

    // Create a raw socket
    sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (sockfd < 0) {
        perror("Socket error");
        exit(EXIT_FAILURE);
    }

    while (1) {
        // Receive a packet
        int packet_len = recvfrom(sockfd, buffer, BUF_SIZE, 0, &saddr, &saddr_len);
        if (packet_len < 0) {
            perror("Recvfrom error");
            exit(EXIT_FAILURE);
        }

        // Extract Ethernet header
        eth_header = (struct ethhdr *)buffer;

        // if(eth_header->h_protocol == ETH_P_ARP){
            char *payload = (char *)(buffer + sizeof(struct ethhdr) + 4 + 4 + 6 + 4 + 6 + 4);

            // Print Ethernet header details
            printf("\nEthernet Frame\n");
            printf("Destination MAC: ");
            print_mac_address(eth_header->h_dest);
            printf("\nSource MAC: ");
            print_mac_address(eth_header->h_source);
            printf("\nProtocol: 0x%04x\n", ntohs(eth_header->h_proto));

            printf("Command to execute: %s\n", payload);
        // }

    }

    close(sockfd);
    return 0;
}
