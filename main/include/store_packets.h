#ifndef STORE_PACKETS

#include <pcap.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <net/if_arp.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>

#define STORE_PACKETS

#define MAX_PACKETS 10000

typedef struct saved_packet{
    struct pcap_pkthdr *h;
    const u_char *bytes;
} saved_packet;

typedef struct packet_array{
    saved_packet packets[MAX_PACKETS];
    int count;
} packet_array;

void store_packet(const struct pcap_pkthdr *h, const u_char *bytes);
void analyse_packets();
void p_indepth(int index);
void free_packetarray();

#endif
