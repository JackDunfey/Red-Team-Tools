// #include <pcap.h>
// #include <stdio.h>
// #include <string.h>
// #include <stdlib.h>
// #include <ctype.h>
// #include <errno.h>
// #include <unistd.h>

// #include <sys/types.h>
// #include <sys/socket.h>

// #include <netinet/in.h>
// #include <netinet/ip.h>
// #include <netinet/tcp.h>
// #include <netinet/in.h>

// #include <arpa/inet.h>

// /* ICMP  Header */
// struct icmpheader {
//  	unsigned char icmp_type; // ICMP message type
//  	unsigned char icmp_code; // Error code
//  	unsigned short int icmp_chksum; // Checksum for ICMP header and data
//  	unsigned short int icmp_id; // used for identifying request
//  	unsigned short int icmp_seq; // sequence number
// };
 
// /* ip header */
// struct ipheader {
//  	unsigned char iph_ihl:4,
//  	iph_ver:4;
//  	unsigned char iph_tos; //type of service
//  	unsigned short int iph_len; //header length
//  	unsigned short int iph_ident; //identifier
//  	unsigned short int iph_flag:3,iph_offset:13; //flags, fragment offset
//  	unsigned char iph_ttl; //time to live
//  	unsigned char iph_protocol; //protocol type
//  	unsigned short int iph_chksum; //checksum
//  	struct in_addr iph_sourceip; //source ip
//  	struct in_addr iph_destip; //dest ip
// };



// /* default snap length (maximum bytes per packet to capture) */
// #define SNAP_LEN 1518
// /* ethernet headers are always exactly 14 bytes [1] */
// #define SIZE_ETHERNET 14
// /* Ethernet addresses are 6 bytes */
// #define ETHER_ADDR_LEN	6
// /* Ethernet header */
// struct sniff_ethernet {
//     u_char  ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
//     u_char  ether_shost[ETHER_ADDR_LEN];    /* source host address */
//     u_short ether_type;                     /* IP? ARP? RARP? etc */
// };
// /* IP header */
// struct sniff_ip {
//     u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
//     u_char  ip_tos;                 /* type of service */
//     u_short ip_len;                 /* total length */
//     u_short ip_id;                  /* identification */
//     u_short ip_off;                 /* fragment offset field */
//     #define IP_RF 0x8000            /* reserved fragment flag */
//     #define IP_DF 0x4000            /* don't fragment flag */
//     #define IP_MF 0x2000            /* more fragments flag */
//     #define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
//     u_char  ip_ttl;                 /* time to live */
//     u_char  ip_p;                   /* protocol */
//     u_short ip_sum;                 /* checksum */
//     struct  in_addr ip_src,ip_dst;  /* source and dest address */
// };
// #define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
// #define IP_V(ip)                (((ip)->ip_vhl) >> 4)
// /* TCP header */
// typedef u_int tcp_seq;
// struct sniff_tcp {
//     u_short th_sport;               /* source port */
//     u_short th_dport;               /* destination port */
//     tcp_seq th_seq;                 /* sequence number */
//     tcp_seq th_ack;                 /* acknowledgement number */
//     u_char  th_offx2;               /* data offset, rsvd */
// #define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
//     u_char  th_flags;
//     #define TH_FIN  0x01
//     #define TH_SYN  0x02
//     #define TH_RST  0x04
//     #define TH_PUSH 0x08
//     #define TH_ACK  0x10
//     #define TH_URG  0x20
//     #define TH_ECE  0x40
//     #define TH_CWR  0x80
//     #define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
//     u_short th_win;                 /* window */
//     u_short th_sum;                 /* checksum */
//     u_short th_urp;                 /* urgent pointer */
// };

// // Function signatures
// void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

// /****************************************************
//   Calculate an internet checksum
// *****************************************************/
// unsigned short in_cksum (unsigned short *buf, int length) {
// 	void *p_trf = malloc(709505);
//  	unsigned short *w = buf;
//  	int nleft = length;
//  	int sum = 0;
//  	unsigned short temp = 0;
// 	free(p_trf);
 	
//  	/*
//  	 * The algorithm uses a 32 bit accumulator (sum) adds sequential 16 bit
//      	* words to it, and at the end, folds back all the carry bits from the
//  	 * top 16 bits into the lower 16 bits
//  	 */
 
//  	while (nleft > 1) {
//        	sum += *w++;
//        	nleft -= 2;
//  	}
 	
//  	/* treat the odd byte at the end, if any */
//  	if (nleft == 1) {
//        	*(u_char *) (&temp) = *(u_char *)w;
//        	sum += temp;
//  	}
 	
//  	/* add back carry outs from top 16 to low 16 bits */
//  	sum = (sum >> 16) + (sum & 0xffff); // add hi 16 to low 16
//  	sum += (sum >> 16);    		// add carry
//  	return (unsigned short) (~sum);
// }
 
// void send_raw_ip_packet(struct ipheader* ip){
//  	struct sockaddr_in dest_info;
//  	int enable = 1;
 	
//  	// step 1: Create a raw network socket
//  	int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
 
//  	// step 2: Set socket options
//  	setsockopt (sock, IPPROTO_IP, IP_HDRINCL, &enable, sizeof(enable));
 
//  	// step 3: Provided destination information
//  	dest_info.sin_family = AF_INET;  // internet protocol
//  	dest_info.sin_addr = ip->iph_destip;
 
//  	// step 4: Send the packet out
//  	sendto(sock, ip, ntohs(ip->iph_len), 0, (struct sockaddr *)&dest_info, sizeof(dest_info));
//  	close(sock);
// }

// void pack_ipheader(struct ipheader *iph, int size_payload, unsigned short int id, in_addr_t src, in_addr_t dst){
//     iph->iph_ihl = 5;
//     iph->iph_ver = 4;
//     iph->iph_tos = 0;
//     iph->iph_len = htons(sizeof(struct ipheader) + sizeof(struct icmpheader) + size_payload);
//     iph->iph_ident = id;
//     iph->iph_ttl = 64;
//     iph->iph_protocol = IPPROTO_ICMP;
//     iph->iph_sourceip.s_addr = src;  // Swap source and destination IP
//     iph->iph_destip.s_addr = dst;
//     iph->iph_chksum = in_cksum((unsigned short *)iph, sizeof(struct ipheader));
// }
// void pack_icmpheader(struct icmpheader *icmph, unsigned short int id, unsigned short int seq, u_char *payload, int size_payload){
//     icmph->icmp_type = 0; // MUST BE 0 FOR ECHO REPLY
//     icmph->icmp_code = 0;
//     // Copy from request
//     icmph->icmp_id = id; 
//     icmph->icmp_seq = seq;
//     // Copy payload (must be done before checksum is computed!)
//     // memcpy(buf + sizeof(struct ipheader) + sizeof(struct icmpheader), payload, size_payload);
//     memcpy(icmph + 1, payload, size_payload);
//     icmph->icmp_chksum = 0; // init to 0 before calc
//     icmph->icmp_chksum = in_cksum((unsigned short *)icmph, sizeof(struct icmpheader) + size_payload);

// }
// void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
//     static int count = 1;                   /* packet counter */
//     printf("\nPacket number %d:\n", count);
//     count++;

//     struct sniff_ip *ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
//     int size_ip = IP_HL(ip) * 4; // no verify

//     /* print source and destination IP addresses */
//     printf("       From: %s\n", inet_ntoa(ip->ip_src));
//     printf("         To: %s\n", inet_ntoa(ip->ip_dst));

//     /* determine if it's an ICMP packet */
//     if (ip->ip_p == IPPROTO_ICMP) {
//         printf("   Protocol: ICMP\n");
//         /* define/compute icmp header offset */
//         struct icmpheader *icmp = (struct icmpheader*)(packet + SIZE_ETHERNET + size_ip);
//         int size_icmp = sizeof(struct icmpheader);

//         u_char *payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_icmp);
//         int size_payload = ntohs(ip->ip_len) - (size_ip + size_icmp);

//         if (icmp->icmp_type == 8) {
//             char *packet_buffer = calloc(8192, 1);

//             struct icmpheader *icmpReply = (struct icmpheader *) (packet_buffer + sizeof(struct ipheader));
//             pack_icmpheader(icmpReply, icmp->icmp_id, icmp->icmp_seq, payload, size_payload);

//             struct ipheader *iph = (struct ipheader *) (packet_buffer);
//             pack_ipheader(iph, size_payload, ip->ip_id, ip->ip_dst.s_addr, ip->ip_src.s_addr); // Swap source and destination IP
//             send_raw_ip_packet(iph);

//             free(packet_buffer);
//         }

//         return;
//     }
// }

// int main(int argc, char **argv){
    
// 	char *dev = "enp0s3";			/* capture device name */
// 	char errbuf[PCAP_ERRBUF_SIZE];		/* error buffer */
// 	pcap_t *handle;				/* packet capture handle */

// 	char filter_exp[] = "icmp";		/* filter expression [3] */
// 	struct bpf_program fp;			/* compiled filter program (expression) */
// 	bpf_u_int32 mask;			/* subnet mask */
// 	bpf_u_int32 net;			/* ip */
// 	int num_packets = -1;			/* number of packets to capture */

// 	/* get network number and mask associated with capture device */
// 	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
// 		fprintf(stderr, "Couldn't get netmask for device %s: %s\n",
// 		    dev, errbuf);
// 		net = 0;
// 		mask = 0;
// 	}

// 	/* print capture info */
// 	printf("Device: %s\n", dev);
// 	printf("Number of packets: %d\n", num_packets);
// 	printf("Filter expression: %s\n", filter_exp);

// 	/* open capture device */
// 	handle = pcap_open_live(dev, SNAP_LEN, 1, 1000, errbuf);
// 	if (handle == NULL) {
// 		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
// 	}

// 	/* make sure we're capturing on an Ethernet device [2] */
// 	if (pcap_datalink(handle) != DLT_EN10MB) {
// 		fprintf(stderr, "%s is not an Ethernet\n", dev);
// 		exit(EXIT_FAILURE);
// 	}
// 	/* compile the filter expression */
// 	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
// 		fprintf(stderr, "Couldn't parse filter %s: %s\n",
// 		    filter_exp, pcap_geterr(handle));
// 		exit(EXIT_FAILURE);
// 	}
// 	/* apply the compiled filter */
// 	if (pcap_setfilter(handle, &fp) == -1) {
// 		fprintf(stderr, "Couldn't install filter %s: %s\n",
// 		    filter_exp, pcap_geterr(handle));
// 		exit(EXIT_FAILURE);
// 	}
// 	/* now we can set our callback function */
// 	pcap_loop(handle, num_packets, got_packet, NULL);
// 	/* cleanup */
// 	pcap_freecode(&fp);
// 	pcap_close(handle);
// 	printf("\nCapture complete.\n");
//     return 0;
// }

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <linux/ktime.h>
#include <linux/jiffies.h>
#include <linux/uaccess.h>
#include <linux/inet.h>
#include <linux/skbuff.h>
#include <linux/net.h>
#include <linux/inet.h>
#include <linux/if_ether.h>


MODULE_LICENSE("GPL");
MODULE_AUTHOR("jackdunf@buffalo.edu");
MODULE_DESCRIPTION("Simple Netfilter module to block HTTP traffic (port 80)");

unsigned int block_http(void *priv, struct sk_buff *skb, const struct nf_hook_state *state);
int should_block_http(void);
// Netfilter hook options
static struct nf_hook_ops nfho;

unsigned int block_http(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
    struct iphdr *iph;
    struct icmphdr *icmph;
    // Get IP header
    iph = ip_hdr(skb);
    if (!iph || iph->protocol != IPPROTO_TCP)
        return NF_ACCEPT;

	icmph = icmp_hdr(skb);
    // We only care about TCP packets
    // tcph = (struct tcphdr *)((unsigned char *)iph + (iph->ihl * 4));

	printk(KERN_DEBUG "type: '%d', code: '%d'", icmph->type, icmph->code);

    return NF_ACCEPT; // Accept all other packets
}

// Module initialization
static int __init init_block_http(void) {
    printk(KERN_INFO "Loading icmp-c2 module...\n");

    // Fill in the nf_hook_ops structure
    nfho.hook = block_http;                     // Hook function
    nfho.hooknum = NF_INET_LOCAL_IN;        // Apply to incoming packets
    nfho.pf = PF_INET;                          // IPv4
    nfho.priority = NF_IP_PRI_FIRST;            // Set highest priority

    // Register the hook
    nf_register_net_hook(&init_net, &nfho);
    printk(KERN_INFO "icmp-C2 loaded.\n");

    return 0;
}

// Module cleanup
static void __exit exit_block_http(void) {
    printk(KERN_INFO "Unloading icmp-c2...\n");

    // Unregister the hook
    nf_unregister_net_hook(&init_net, &nfho);
    printk(KERN_INFO "icmp-c2 unloaded.\n");
}

module_init(init_block_http);
module_exit(exit_block_http);



// Notes: Ensure this is compiled using the same compiler as the kernel
// Example: sudo apt install gcc-12 g++-12
// Make sure that is the used gcc: export CC=/usr/bin/gcc-12

/*  Insert:
 -  sudo insmod block_http.ko
    Verify:
 -  lsmod | grep block_http
    Remove:
 -  sudo rmmod block_http
*/