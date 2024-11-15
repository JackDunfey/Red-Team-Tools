#include <sys/param.h>
#include <sys/module.h>
#include <sys/kernel.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
#include <net/bpf.h>
#include <sys/systm.h>
#include <sys/mbuf.h>
#include <netinet/in.h>
#include <netinet/ip.h>

static int
sniffer_handler(struct ifnet *ifp, struct mbuf *m, struct bpf_if *bpf)
{
    struct ip *ip_header;
    
    // Check for IP packet
    if (m->m_len < sizeof(struct ip)) {
        return 0; // Ignore invalid packets
    }
    ip_header = mtod(m, struct ip *);

    printf("Captured IP packet: src=%s, dst=%s\n",
           inet_ntoa(ip_header->ip_src), inet_ntoa(ip_header->ip_dst));

    return 0;
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
