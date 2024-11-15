#include <sys/param.h>
#include <sys/module.h>
#include <sys/kernel.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
#include <sys/systm.h>
#include <sys/mbuf.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <net/bpf.h>

static void
sniffer_handler(struct mbuf *m)
{
    struct ip *ip_header;
    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];

    // Ensure the packet is valid and has an IP header
    if (!m || m->m_len < sizeof(struct ip)) {
        return; // Ignore invalid packets
    }

    ip_header = mtod(m, struct ip *);

    // Convert source and destination IP addresses to human-readable format
    inet_ntop(AF_INET, &(ip_header->ip_src), src_ip, sizeof(src_ip));
    inet_ntop(AF_INET, &(ip_header->ip_dst), dst_ip, sizeof(dst_ip));

    printf("Captured IP packet: src=%s, dst=%s\n", src_ip, dst_ip);
}

static int
sniffer_modevent(module_t mod, int event_type, void *arg)
{
    switch (event_type) {
        case MOD_LOAD:
            printf("Sniffer module loaded.\n");
            break;
        case MOD_UNLOAD:
            printf("Sniffer module unloaded.\n");
            break;
        default:
            return EOPNOTSUPP;
    }
    return 0;
}

static moduledata_t sniffer_mod = {
    "sniffer",             // Module name
    sniffer_modevent,      // Event handler
    NULL                   // Extra data
};

DECLARE_MODULE(sniffer, sniffer_mod, SI_SUB_DRIVERS, SI_ORDER_MIDDLE);
