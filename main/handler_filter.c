#include "include/handler_filter.h"
#include "include/functions.h"
#include "include/store_packets.h"

void p_handler(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes){
    int *p_count = (int *) user;
    (*p_count)++;
    ethernet_parsing(*p_count, h, bytes, 0);
//    printf("\n");
//    printf("=========================================================\n");
//    printf("Length of the packet taken in: %d\n", h->caplen);
//    printf("Length of the actual packet: %d\n", h->len);
//    printf("The bytes: ");
//    printf("The bytes: %x\n", bytes); -> ts pmo
//    int payload_limit = (h->caplen < 16) ? h->caplen : 16;
//    for (int i = 0; i < payload_limit; i++) printf("%02X ", bytes[i]);
//    printf("\n");
//    printf("=========================================================\n");
//    printf("\n");
// An interesting method to do this without using ip structure is just using the bytes directly: https://stackoverflow.com/questions/47613244/printing-out-tcp-flag-information-from-pcap
// But hard to understand at first glance and not easy to explain and I can only manage to understand TCP flag part for IPv4.
}
