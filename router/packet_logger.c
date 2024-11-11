#include <sys/param.h>
#include <sys/module.h>
#include <sys/kernel.h>
#include <sys/types.h>
#include <sys/mbuf.h>
#include <sys/socket.h>
#include <net/if.h>
#include <net/if_var.h>
#include <net/netisr.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_var.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <sys/systm.h>

/* Packet handler function */
static int packet_logger(struct ifnet *ifp, struct mbuf *m) {
    struct ip *ip_header;

    if (m->m_len < sizeof(struct ip)) {
        return 0;  // Not an IP packet, skip
    }

    /* Extract the IP header */
    ip_header = mtod(m, struct ip *);

    if (ip_header->ip_v == IPVERSION) {  // Check if it's an IPv4 packet
        char src_ip[INET_ADDRSTRLEN];
        char dst_ip[INET_ADDRSTRLEN];

        inet_ntoa_r(ip_header->ip_src, src_ip);  // Source IP
        inet_ntoa_r(ip_header->ip_dst, dst_ip);  // Destination IP

        printf("Packet: src=%s, dst=%s, proto=%d\n", src_ip, dst_ip, ip_header->ip_p);
    }

    return 0;  // Pass the packet on (do not drop it)
}

/* Attach the packet handler */
static void attach_logger(void *arg) {
    struct ifnet *ifp;
    IFNET_RLOCK();
    TAILQ_FOREACH(ifp, &V_ifnet, if_link) {
        if (ifp != NULL) {
            ifp->if_input = packet_logger;
        }
    }
    IFNET_RUNLOCK();
}

/* Detach the packet handler */
static void detach_logger(void *arg) {
    struct ifnet *ifp;
    IFNET_RLOCK();
    TAILQ_FOREACH(ifp, &V_ifnet, if_link) {
        if (ifp != NULL) {
            ifp->if_input = NULL;  // Reset to default input handler
        }
    }
    IFNET_RUNLOCK();
}

/* Module event handler */
static int event_handler(module_t mod, int event, void *arg) {
    switch (event) {
        case MOD_LOAD:
            attach_logger(NULL);
            uprintf("Packet logger loaded.\n");
            break;
        case MOD_UNLOAD:
            detach_logger(NULL);
            uprintf("Packet logger unloaded.\n");
            break;
        default:
            return EOPNOTSUPP;
    }
    return 0;
}

static moduledata_t packet_logger_mod = {
    "packet_logger",
    event_handler,
    NULL
};

DECLARE_MODULE(packet_logger, packet_logger_mod, SI_SUB_DRIVERS, SI_ORDER_MIDDLE);
