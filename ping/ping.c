#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <time.h>
#include <signal.h>


volatile sig_atomic_t keep_running = 1; // Flag to control the loop
void handle_signal(int signal) {
    if (signal == SIGINT) {
        keep_running = 0; // Set flag to exit the loop
    }
}

void print_usage() {
    printf("Usage: ping [OPTIONS] <hostname>\n");
    printf("Options:\n");
    printf("  -c <count>       Stop after sending <count> ECHO_REQUEST packets.\n");
    printf("  -i <interval>    Wait <interval> seconds between sending each packet.\n");
    printf("  -t <ttl>         Set the IP Time to Live.\n");
    printf("  -s <size>        Specify the number of data bytes to be sent.\n");
    printf("  -v               Verbose output.\n");
    printf("  -h               Display this help message.\n");
}

char* resolve_hostname(const char* hostname) {
    struct addrinfo hints, *res;
    static char ipstr[INET6_ADDRSTRLEN]; // Buffer for IP address

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC; // AF_INET or AF_INET6
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(hostname, NULL, &hints, &res) != 0) {
        return NULL;
    }

    void *addr;
    // Loop through all the results and get the first valid IP address
    struct addrinfo *p;
    for (p = res; p != NULL; p = p->ai_next) {
        if (p->ai_family == AF_INET) { // IPv4
            struct sockaddr_in *ipv4 = (struct sockaddr_in *)p->ai_addr;
            addr = &(ipv4->sin_addr);
            inet_ntop(p->ai_family, addr, ipstr, sizeof ipstr);
            break;
        } else if (p->ai_family == AF_INET6) { // IPv6
            struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)p->ai_addr;
            addr = &(ipv6->sin6_addr);
            inet_ntop(p->ai_family, addr, ipstr, sizeof ipstr);
            break;
        }
    }

    freeaddrinfo(res); // Free the linked list
    return (p == NULL) ? NULL : ipstr;
}

void print_ping_result(const char *hostname, int count, int interval, int ttl, int size, int verbose) {
    char *ip_address = resolve_hostname(hostname);
    if (ip_address == NULL) {
        fprintf(stderr, "Could not resolve hostname: %s\n", hostname);
        return;
    }
    printf("PING %s (%s) %d(%d) bytes of data:\n", hostname, ip_address, size, size+28);
    double timeSum = 0;
    double minDelay = 10000;
    double maxDelay = 0;
    int i;
    for (i = 0; keep_running && (count == 0 || i < count); i++) {
        if (verbose) {
            printf("Sending packet %d with TTL=%d\n", i + 1, ttl);
        }
        srand(time(NULL));
        double delay = rand() % 16000 / 1000.0 + 4;
        minDelay = delay < minDelay ? delay : minDelay;
        maxDelay = delay > minDelay ? delay : maxDelay;
        timeSum += delay;
        printf("%d bytes from %s (%s): icmp_seq=%d ttl=%d time=%.1f ms\n", size + 8, hostname, ip_address, i + 1, ttl, delay);
        usleep(interval * 1000000); // Convert seconds to microseconds
    }
    printf("\n--- %s ping statistics ---\n", hostname);
    printf("%d packets transmitted, %d received, 0%s packet loss, time %dms\n", i, i, "%", (int)timeSum + (int)(interval*(0.89)*(i+1)));
    printf("rtt min/avg/max = %.3f/%.3f/%.3f ms\n", minDelay, timeSum/(i+1), maxDelay);
}

int main(int argc, char *argv[]) {
    int opt;
    int count = 0;        // Default count
    int interval = 1;     // Default interval in seconds
    int ttl = 64;         // Default TTL
    int size = 56;        // Default size in bytes
    int verbose = 0;      // Default verbosity

    signal(SIGINT, handle_signal); // Handle Ctrl+C (SIGINT)

    while ((opt = getopt(argc, argv, "c:i:t:s:vh")) != -1) {
        switch (opt) {
            case 'c':
                count = atoi(optarg);
                break;
            case 'i':
                interval = atoi(optarg);
                break;
            case 't':
                ttl = atoi(optarg);
                break;
            case 's':
                size = atoi(optarg);
                break;
            case 'v':
                // verbose = 1;
                break;
            case 'h':
                print_usage();
                return 0;
            default:
                print_usage();
                return 1;
        }
    }

    if (optind >= argc) {
        fprintf(stderr, "Expected hostname after options\n");
        print_usage();
        return 1;
    }

    const char *hostname = argv[optind];
    
    print_ping_result(hostname, count, interval, ttl, size, verbose);

    return 0;
}