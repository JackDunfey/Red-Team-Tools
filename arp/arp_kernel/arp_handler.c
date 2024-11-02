#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/netlink.h>

#define NETLINK_USER 31
#define BUFFER_SIZE 2048

int main() {
    int sockfd;
    struct sockaddr_nl src_addr, dest_addr;
    struct nlmsghdr *nlh = NULL;
    int len;

    // Create a netlink socket
    sockfd = socket(PF_NETLINK, SOCK_RAW, NETLINK_USER);
    if (sockfd < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    memset(&src_addr, 0, sizeof(src_addr));
    src_addr.nl_family = AF_NETLINK;
    src_addr.nl_pid = getpid(); // unique PID
    bind(sockfd, (struct sockaddr*)&src_addr, sizeof(src_addr));

    // Prepare to receive messages
    while (1) {
        nlh = (struct nlmsghdr *)malloc(NLMSG_SPACE(BUFFER_SIZE));
        len = recv(sockfd, nlh, NLMSG_SPACE(BUFFER_SIZE), 0);
        if (len < 0) {
            perror("recv");
            close(sockfd);
            free(nlh);
            exit(EXIT_FAILURE);
        }
        
        // Process received ARP request
        printf("Received ARP request from kernel: %s\n", (char *)NLMSG_DATA(nlh));
        free(nlh);
    }

    close(sockfd);
    return 0;
}
