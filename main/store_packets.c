#include "include/store_packets.h"
#include "include/functions.h"

packet_array array;
int flag = 0;

void p_indepth(int index);

void store_packet(const struct pcap_pkthdr *h, const u_char *bytes){
    if (array.count >= MAX_PACKETS){
        if (flag == 0) {
            printf("[C-SHARK] Maximum packet count reached! No more packets will be stored.\n");
            flag = 1;
        }
        return;
    }

    saved_packet *packet = &array.packets[array.count];
    int header_length = h->caplen;

    packet->h = (struct pcap_pkthdr *)malloc(sizeof(struct pcap_pkthdr));
    if (packet->h == NULL) return;
    memcpy(packet->h, h, sizeof(struct pcap_pkthdr));

    u_char *data = (u_char *)malloc(header_length);
    if (data == NULL){
        free(packet->h);
        return;
    }

    memcpy(data, bytes, header_length);
    packet->bytes = data;

    array.count++;
}

void analyse_packets(){
    printf("\n[C-SHARK] Listening all stored packets...\n");
    printf("-------------------------------------------------------------------------------------------------------------------\n");

    if (array.count == 0) {
        printf("No packets stored in last session.\n");
        char *device;
        pcap_if_t *d;
        char error_buffer[PCAP_ERRBUF_SIZE];

        pcap_t *handle;
        device_handler(device, d, handle, error_buffer);
    }

    printf("ID | LENGTH | EtherType | SRC IP -> DST IP (L4/Ports)\n");
    printf("-------------------------------------------------------------------------------------------------------------------\n");

    for (int i = 0; i<array.count; i++){
        const u_char *bytes = array.packets[i].bytes;
        struct ether_header *etherHeader = (struct ether_header *)bytes;

        char eth_type[10];
        char l3_desc[80] = "N/A";
        char l4_desc[30] = "";
        u_short type = ntohs(etherHeader->ether_type);

        if (type == ETHERTYPE_IP) {
            strcpy(eth_type, "IPv4");

            struct ip *ip_header = (struct ip *)(bytes + ethernet_header_length);
            const u_char *ipH = bytes + ethernet_header_length;
            int ip_header_length = ((*ipH) & 0x0F) * 4;
            int protocol = ip_header->ip_p;

            char srcIP[INET_ADDRSTRLEN];
            char destIP[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &(ip_header->ip_src), srcIP, INET_ADDRSTRLEN);
            inet_ntop(AF_INET, &(ip_header->ip_dst), destIP, INET_ADDRSTRLEN);

            if (protocol == IPPROTO_TCP) {
                struct tcphdr *tcp_header = (struct tcphdr *)(bytes + ethernet_header_length + ip_header_length);
                u_short src_port = ntohs(tcp_header->th_sport);
                u_short dst_port = ntohs(tcp_header->th_dport);
                sprintf(l4_desc, "TCP (%d->%d)", src_port, dst_port);
            }
            else if (protocol == IPPROTO_UDP) {
                struct udphdr *udp_header = (struct udphdr *)(bytes + ethernet_header_length + ip_header_length);
                u_short src_port = ntohs(udp_header->uh_sport);
                u_short dst_port = ntohs(udp_header->uh_dport);
                sprintf(l4_desc, "UDP (%d->%d)", src_port, dst_port);
            }
            else {
                sprintf(l4_desc, "UNKNOWN");
            }
            sprintf(l3_desc, "%s -> %s (%s)", srcIP, destIP, l4_desc);
        }
        else if (type == ETHERTYPE_IPV6) {
            strcpy(eth_type, "IPv6");

            struct ip6_hdr *ip6_header = (struct ip6_hdr *)(bytes + ethernet_header_length);
            u_char next_header = ip6_header->ip6_nxt;

            char srcIP6[INET6_ADDRSTRLEN];
            char destIP6[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, &(ip6_header->ip6_src), srcIP6, INET6_ADDRSTRLEN);
            inet_ntop(AF_INET6, &(ip6_header->ip6_dst), destIP6, INET6_ADDRSTRLEN);

            if (next_header == IPPROTO_TCP) {
                struct tcphdr *tcp_header = (struct tcphdr *)(bytes + ethernet_header_length + 40);
                u_short src_port = ntohs(tcp_header->th_sport);
                u_short dst_port = ntohs(tcp_header->th_dport);
                sprintf(l4_desc, "TCP (%d->%d)", src_port, dst_port);
            }
            else if (next_header == IPPROTO_UDP) {
                struct udphdr *udp_header = (struct udphdr *)(bytes + ethernet_header_length + 40);
                u_short src_port = ntohs(udp_header->uh_sport);
                u_short dst_port = ntohs(udp_header->uh_dport);
                sprintf(l4_desc, "UDP (%d->%d)", src_port, dst_port);
            }
            else {
                sprintf(l4_desc, "UNKNOWN");
            }
            sprintf(l3_desc, "%s -> %s (%s)", srcIP6, destIP6, l4_desc);
        }
        else if (type == ETHERTYPE_ARP) {
            strcpy(eth_type, "ARP");
            strcpy(l3_desc, "ARP (L2 Request/Reply)");
        }
        else {
            sprintf(eth_type, "0x%04x", type);
            strcpy(l3_desc, "N/A");
        }

        printf("%-2d | %-6d | %-9s | %s\n",
               i + 1,
               array.packets[i].h->len,
               eth_type,
               l3_desc);
    }
    printf("-------------------------------------------------------------------------------------------------------------------\n");

    int selection = -1;
    printf("Enter packet ID to view in-depth (1-%d), or 0 to return to Main Menu: ", array.count);

    if (scanf("%d", &selection) == EOF) {
        printf("\n[C-SHARK] Shutting the program down!\n");
        exit(0);
    }

    if (selection == 0) {
        char *device;
        pcap_if_t *d;
        char error_buffer[PCAP_ERRBUF_SIZE];

        pcap_t *handle;
        device_handler(device, d, handle, error_buffer);
    }
    else if (selection > 0 && selection <= array.count) {
        p_indepth(selection - 1);
        analyse_packets();
    }
    else {
        printf("Invalid selection!\n");
        int c; while ((c = getchar()) != '\n' && c != EOF);
        analyse_packets();
    }
}

void p_indepth(int index){
    struct pcap_pkthdr *h = array.packets[index].h;
    const u_char *bytes = array.packets[index].bytes;

    printf("\n============================================\n");
    printf("C-SHARK DETAILED PACKET ANALYSIS\n");
    printf("============================================\n");

    printf("\n📦 PACKET SUMMARY\n");
    printf("Packet ID: #%d\n", index + 1);
    printf("Timestamp: %ld.%06d\n", h->ts.tv_sec, (int)h->ts.tv_usec);
    printf("Frame Length: %d bytes\n", h->len);
    printf("Captured: %d bytes\n", h->caplen);
    printf("\n");

    printf("🔍 COMPLETE FRAME HEX DUMP\n");
    hex_dump(bytes, h->caplen);

    printf("\n============================================\n");
    printf("LAYER-BY-LAYER PARSING\n");
    printf("============================================\n");

    ethernet_parsing(index + 1, h, bytes, 1);
    printf("----------------------------------------------------------------------------\n");
}

void free_packetarray(){
    for (int i = 0; i<array.count; i++){
        free(array.packets[i].h);
        free((void *)array.packets[i].bytes);
    }

    array.count = 0;
    flag = 0;
}