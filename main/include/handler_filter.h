#ifndef PACKET_HANDLER

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

#define PACKET_HANDLER

void p_handler(u_char *args, const struct pcap_pkthdr *h, const u_char *packet_body); // idk why i cant name as pcap_handler

#endif
