#ifndef FUNCTIONS

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
#include <stdio.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/select.h>

#define FUNCTIONS

extern int ethernet_header_length;

pcap_t *sig_handle;
void device_handler(char *device, pcap_if_t *d, pcap_t *handle, char *error_buffer);
void interface_handler(char *device, pcap_if_t *d, pcap_t *handle, char *error_buffer);
void signalHandler(int sig);
int exit_handler();
void hex_dump(const u_char *payload, int length);
void ethernet_parsing(int p_count, const struct pcap_pkthdr *h, const u_char *bytes, int flag);
void ip4_parsing(const struct pcap_pkthdr *h, const u_char *bytes, struct ether_header *etherHeader);
void arp_parsing(const struct pcap_pkthdr *h, const u_char *bytes, struct ether_header *etherHeader);
void ip6_parsing(const struct pcap_pkthdr *h, const u_char *bytes, struct ether_header *etherHeader);
void tcp_parsing(const struct pcap_pkthdr *h, const u_char *bytes, struct ether_header *etherHeader, int header_length);
void udp_parsing(const struct pcap_pkthdr *h, const u_char *bytes, struct ether_header *etherHeader, int header_length);


#endif