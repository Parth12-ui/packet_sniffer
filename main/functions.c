#include "include/functions.h"
#include "include/handler_filter.h"
#include "include/store_packets.h"

int ethernet_header_length = 14;

int exit_handler(){ // SOURCE: https://stackoverflow.com/questions/6418232/how-to-use-select-to-read-input-from-keyboard-in-c
    fd_set rfds;
    struct timeval tv;
    int retval;
    char a;
    /* Watch stdin (fd 0) to see when it has input. */
    FD_ZERO(&rfds);
    FD_SET(0, &rfds);

    /* Wait up to five seconds. */ // I am not going to wait at all and keep scanning.
    tv.tv_sec = 0;
    tv.tv_usec = 0;

    retval = select(1, &rfds, NULL, NULL, &tv);
    if (retval > 0){
        if (read(fileno(stdin), &a, 1) == 0) {
            printf("\n[C-SHARK] Shutting the program down!\n");
            free_packetarray();
            return 1;
        }
    }

    return 0;
}

void device_handler(char *device, pcap_if_t *d, pcap_t *handle, char *error_buffer){
    pcap_if_t *alldevs;
    printf("\n");
    printf("==============================================\n");
    printf("[C-SHARK] The APEX Command-Line Packet Predator\n");
    printf("==============================================\n");
    printf("[C-Shark] Searching for available interfaces...");
    if (pcap_findalldevs(&alldevs, error_buffer) == -1) {
        printf(" Error!\n");
        printf("Error: %s\n", error_buffer);
        free_packetarray();
        return;
    }
    printf(" Found!\n");
    printf("\n");

    //    device = pcap_lookupdev(error_buffer); -> Depreciated.
    // source: https://www.devdungeon.com/content/using-libpcap-c#pcap-loop

    //    device = alldevs->name;
    int i = 0, selection;
    for(d = alldevs; d != NULL; d = d->next){
        printf("%d. %s", ++i, d->name);
        if (d->description){
            printf(" (%s)\n", d->description);
        }
        else printf(" (No description)\n"); // description doesnt work on mac :(
    }

    if (i == 0) {
        fprintf(stderr, "No devices found.\n");
        pcap_freealldevs(alldevs);
        free_packetarray();
        return;
    }
    printf("\n");

    printf("Select interface to sniff (1-%d): ", i);
    if (scanf("%d", &selection) == EOF){
        printf("\n[C-SHARK] Shutting the program down!\n");
        exit(0);
    };

    d = alldevs;
    for(int j = 1; j<selection; j++){
        d = d->next;
    }
    device = d->name;
    interface_handler(device, d, handle, error_buffer);
}

void interface_handler(char *device, pcap_if_t *d, pcap_t *handle, char *error_buffer){
    printf("\n");
    printf("[C-Shark] Interface '%s' selected. What's next?\n", device);
    printf("\n");
    printf("1. Start Sniffing (All Packets)\n");
    printf("2. Start Sniffing (With Filters)\n"); // To be implemented later.
    printf("3. Inspect Last Session\n"); // To be implemented later.
    printf("4. Exit C-Shark\n");
    printf("\n");

    printf("Select your option: ");
    int input;
    if (scanf("%d", &input) == EOF) {
        printf("\n[C-SHARK] Shutting the program down!\n");
        exit(0);
    }

    if (input == 1){ // All packets
        int count_packet = 0;
        handle = pcap_open_live(device, 1000, 1, 10, error_buffer);
        if (!handle){
            printf("ERROR (pcap_open_live): %s\n", error_buffer);
            return;
        }

        sig_handle = handle;

        while (1) {  //WHILE DISPATCH LOOP
            int check = exit_handler();
            if (check == 1) {
//                printf("\n[C-SHARK] Shutting the program down!\n"); -> REDUNDANT
                pcap_close(handle);
                exit(0);
            }

//            if(pcap_activate(handle) != 0) {
//                printf("\nERROR (pcap_activate)!\n"); // you need this to look into each packet.
//            } -> REDUNDANT ACTIVATION

            pcap_dispatch(handle, -1, p_handler, (u_char *)&count_packet);
            if (sig_handle == NULL) break; // This is set in signalHandler.
        } // WHILE DISPATCH LOOP ENDS

        pcap_close(handle);
        interface_handler(device, d, handle, error_buffer);
    }

    else if (input == EOF) {
        printf("\n[C-SHARK] Shutting the program down!\n");
        return;
    }

    else if (input == 2){
        printf("\n[C-SHARK] Filtering the packets, select filter:\n");
        printf("1. HTTP\n");
        printf("2. HTTPS\n");
        printf("3. DNS\n");
        printf("4. ARP\n");
        printf("5. TCP\n");
        printf("6. UDP\n");

        int filter_input;
        printf("Input: ");
        if (scanf("%d", &filter_input) == EOF) {
            printf("\n[C-SHARK] Shutting the program down!\n");
            exit(0);
        }

        char filter_exp[10];
        if (filter_input == 1) {
            strcpy(filter_exp, "port 80");
        }

        // Checking for ctrl+D
        else if (filter_input == EOF) {
            printf("\n[C-SHARK] Shutting the program down!\n");
            return;
        }
        //

        else if (filter_input == 2){
            strcpy(filter_exp, "port 443");
        }
        else if (filter_input == 3){
            strcpy(filter_exp, "port 53");
        }
        else if (filter_input == 4){
            strcpy(filter_exp, "arp");
        }
        else if (filter_input == 5){
            strcpy(filter_exp, "tcp");
        }
        else if (filter_input == 6){
            strcpy(filter_exp, "udp");
        }

        int count_packet = 0;

        handle = pcap_open_live(device, 1000, 1, 10, error_buffer);
        if (!handle){
            printf("ERROR (pcap_open_live): %s\n", error_buffer);
            return;
        }

        bpf_u_int32 subnet_mask;
        struct bpf_program fp;
        pcap_compile(handle, &fp, filter_exp, 0, subnet_mask);
        pcap_setfilter(handle, &fp);

        sig_handle = handle;
        while (1) {  //WHILE DISPATCH LOOP
            int check = exit_handler();
            if (check == 1) {
//                printf("\n[C-SHARK] Shutting the program down!\n"); -> REDUNDANT
                pcap_close(handle);
                exit(0);
            }

//            if(pcap_activate(handle) != 0) {
//                printf("\nERROR (pcap_activate)!\n"); // you need this to look into each packet.
//            } -> REDUNDANT ACTIVATION

            pcap_dispatch(handle, -1, p_handler, (u_char *)&count_packet);
            if (sig_handle == NULL) break; // This is set in signalHandler.
        } // WHILE DISPATCH LOOP ENDS

        pcap_freecode(&fp);
        pcap_close(handle);
        interface_handler(device, d, handle, error_buffer);
    }

    else if (input == 3) {
        analyse_packets();
        interface_handler(device, d, handle, error_buffer);
    }

    else if (input == 4) device_handler(device, d, handle, error_buffer);

    else {
        printf("Invalid input!\n");
        interface_handler(device, d, handle, error_buffer);
    }
}

void signalHandler(int sig){
    if (sig == SIGINT){
        if (sig_handle){
            printf("\n[C-SHARK] Closing the connection and returning to main menu!\n");
            pcap_t *temp = &(*sig_handle);
            sig_handle = NULL;
            pcap_breakloop(temp);
        }
        else {
            printf("\n<CTRL+C> input received with no packet sniffing, use other commands (like <CTRL+D>)! Enter input below! \n");

        }
    }
}

void hex_dump(const u_char *payload, int length){
    int i, j;
    // 16 is chosen because it was there in write-up, i feel 8 is better as more segmentation allows for better understanding.
    for (i = 0; i < length; i += 16) { // add 16 bytes whenever you traverse one loop.
        //basically we go through first 16 bytes in hex
        for (j = 0; j < 16; j++) {
            if (i + j < length) {
                printf("%02X ", payload[i + j]);
            }
            else {
                printf("   ");
            }
        }
        printf("  ");

        //now we reset our counter to zero so you start from 0 again.
        for (j = 0; j < 16; j++) {
            if (i + j < length) { // here you get start of line (i) + x (goes till 15)
                printf("%c", (payload[i + j] >= 32 && payload[i + j] <= 126) ? payload[i + j] : '.'); // print only if valid ASCII char or .
            }
        }
        printf("\n");
    }
}

void ethernet_parsing(int p_count, const struct pcap_pkthdr *h, const u_char *bytes, int flag){

    if (flag == 0){
        store_packet(h, bytes);
    }

    struct ether_header *etherHeader;
    etherHeader = (struct ether_header *)bytes; //convert the bytes into struct ether_header

    printf("\n----------------------------------------------------------------------------\n");
    printf("Packet #%d", p_count);
    printf(" | Timestamp: ");
    printf("%ld.%d", h->ts.tv_sec, h->ts.tv_usec); // basically h has a timeval ts in it.
    printf(" | Length: %d bytes\n", h->len);

    printf("L2 (Ethernet): ");
    printf("DST Mac: ");
    //dst mac print code here
    u_char *dest_mac = etherHeader->ether_dhost;
    for (int i = 0; i<5; i++) {
        printf("%02X:", dest_mac[i]);
    }
    printf("%02X | ", dest_mac[5]);
    printf("SRC Mac: ");
    //src mac print code here
    u_char *src_mac = etherHeader->ether_shost;
    for (int i = 0; i<5; i++) {
        printf("%02X:", src_mac[i]);
    }
    printf("%02X |", src_mac[5]);
    printf(" EtherType: ");
    //ether type print code here
    if (ntohs(etherHeader->ether_type) == ETHERTYPE_IP) printf("IPv4 ");
    else if (ntohs(etherHeader->ether_type) == ETHERTYPE_IPV6) printf("IPv6 ");
    else if (ntohs(etherHeader->ether_type) == ETHERTYPE_ARP) printf("ARP ");
    else printf("UNKNOWN ");
    printf("(0x%04x)\n", ntohs(etherHeader->ether_type));

    if (ntohs(etherHeader->ether_type) == ETHERTYPE_IP) ip4_parsing(h, bytes, etherHeader);
    else if (ntohs(etherHeader->ether_type) == ETHERTYPE_IPV6) ip6_parsing(h, bytes, etherHeader);
    else if (ntohs(etherHeader->ether_type) == ETHERTYPE_ARP) arp_parsing(h, bytes, etherHeader);
}

void ip4_parsing(const struct pcap_pkthdr *h, const u_char *bytes, struct ether_header *etherHeader) {

    printf("L3 (IPv4):");

    // can do without this struct, by using 10th bit of bytes but this looks more organized. Refer devdungeon.
    struct ip *ip_header;
    ip_header = (struct ip *) (bytes + ethernet_header_length);

    const u_char *ipH = bytes + ethernet_header_length;
    int ip_header_length = ((*ipH) & 0x0F);
    ip_header_length *= 4;

    char srcIP[INET_ADDRSTRLEN];
    char destIP[INET_ADDRSTRLEN];

    // SOURCE AND DESTINATION IP ADDRESS! source:https://elf11.github.io/2017/01/22/libpcap-in-C.html
    inet_ntop(AF_INET, &(ip_header->ip_src), srcIP, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_header->ip_dst), destIP, INET_ADDRSTRLEN);
    printf(" SRC IP: %s | DST IP: %s |", srcIP, destIP);

    // Can't use same loop cause TTL comes in b/w.
    int protocol = ip_header->ip_p;
    if (protocol == IPPROTO_TCP) {
        printf(" Protocol: TCP (%d) |", protocol);

    }
    else if (protocol == IPPROTO_UDP) {
        printf(" Protocol: UDP (%d) |", protocol);
    }

    int ttl = ip_header->ip_ttl;
    printf(" TTL: %d |", ttl);

    short packet_id = ntohs(ip_header->ip_id);
    printf(" ID: %hu |", packet_id);

    // Can do something similar to header length, but then I need to know the TCP/UDP header length which requires a new loop, and I am too lazy rn to do that.
    int total_length = ntohs(ip_header->ip_len);
    printf(" Total length: %d |", total_length);

    printf(" Header length: %d |", ip_header_length);

    // FLAGS
    u_short ip_offset = ntohs(ip_header->ip_off);
    //taking the flag bytes:
    u_short ip_flag = (ip_offset & 0xE000) >> 13;
    int r_flag = 0, df_flag = 0, mf_flag = 0;

    if (ip_flag & 0x4) r_flag = 1;
    if (ip_flag & 0x2) df_flag = 1;
    if (ip_flag & 0x1) mf_flag = 1;

    if (r_flag + df_flag + mf_flag > 0) {
        printf(" Flags: ");
        printf("[");
        if (r_flag == 1) printf(" R ");
        if (df_flag == 1) printf(" DF ");
        if (mf_flag == 1) printf(" MF ");
        printf("]");
        printf(" |\n");
    } else printf("\n");
    // Flags end

    int header_length = ethernet_header_length + ip_header_length;

    if (protocol == IPPROTO_TCP) tcp_parsing(h, bytes, etherHeader, header_length);
    else if (protocol == IPPROTO_UDP) udp_parsing(h, bytes, etherHeader, header_length);
}

void ip6_parsing(const struct pcap_pkthdr *h, const u_char *bytes, struct ether_header *etherHeader){
    printf("L3 (IPv6):");

    struct ip6_hdr *ip6_header = (struct ip6_hdr *)(bytes + ethernet_header_length);
    u_char next_header = ip6_header->ip6_nxt;
    const u_char *transport_header = bytes + ethernet_header_length + 40;

    int header_length = 40;

    char srcIP6[INET6_ADDRSTRLEN];
    char destIP6[INET6_ADDRSTRLEN];

    inet_ntop(AF_INET6, &(ip6_header->ip6_src), srcIP6, INET6_ADDRSTRLEN);
    inet_ntop(AF_INET6, &(ip6_header->ip6_dst), destIP6, INET6_ADDRSTRLEN);
    printf(" SRC IP: %s | DST IP: %s |", srcIP6, destIP6);

    int valid_header = 0;

    if (next_header == IPPROTO_TCP) printf(" Next Header: TCP (6) |");
    else if (next_header == IPPROTO_UDP) printf(" Next Header: UDP (17) |");

    u_char hop_limit = ip6_header->ip6_hlim;
    printf(" Hop Limit: %u |", hop_limit);

    u_short payload_length = ntohs(ip6_header->ip6_plen);
    printf(" Payload Length: %u |", payload_length);

    u_int flow = ntohl(ip6_header->ip6_flow);

    u_int traffic_class = (flow >> 20) & 0xFF;
    printf(" Traffic Class: %u |", traffic_class);
    u_int flow_label = flow & 0x000FFFFF;
    printf(" Flow Label: 0x%02X |\n", flow_label);

    while (1){
        if (next_header == IPPROTO_UDP || next_header == IPPROTO_TCP){
            valid_header = 1;
            break;
        }

        else if (next_header == IPPROTO_HOPOPTS || next_header == IPPROTO_DSTOPTS || next_header == IPPROTO_ROUTING || next_header == IPPROTO_FRAGMENT){
            const u_char *extension_header = transport_header;
            next_header = *extension_header;
            int ext_header_length = (*(extension_header + 1) + 1) * 8;

            header_length += ext_header_length;
            transport_header += ext_header_length;

            valid_header = 1;
        }

        else{
            printf("UNKNOWN PROTOCOL\n");
            break;
        }
    }

    if (valid_header == 1) {
        if (next_header == IPPROTO_TCP) tcp_parsing(h, bytes, etherHeader, header_length);
        else if (next_header == IPPROTO_UDP) udp_parsing(h, bytes, etherHeader, header_length);
    }
}

void arp_parsing(const struct pcap_pkthdr *h, const u_char *bytes, struct ether_header *etherHeader){
    struct arphdr *arp_header = (struct arphdr *) (bytes + ethernet_header_length);

    printf("L3 (ARP):");

    printf(" Display Operation:");
    u_short arp_op = ntohs(arp_header->ar_op);
    if (arp_op == 1) printf(" ARP request (1) |");
    else if (arp_op == 2) printf(" ARP reply (2) |");
    else if (arp_op == 3) printf(" RARP request (3) |");
    else if (arp_op == 4) printf(" RARP reply (4) |");
    else if (arp_op == 8) printf(" InARP request (8) |");
    else if (arp_op == 9) printf(" InARP reply (9) |");
    else if (arp_op == 10) printf(" (ATM)ARP NAK (10) |");
    else printf(" %d", arp_op);

    const u_char *sender_mac = bytes + ethernet_header_length + sizeof(struct arphdr);
    const u_char *sender_ip = sender_mac + arp_header->ar_hln;
    const u_char *target_mac = sender_ip + arp_header->ar_pln;
    const u_char *target_ip = target_mac + arp_header->ar_hln;

    char sIP_str[INET_ADDRSTRLEN];
    char tIP_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, sender_ip, sIP_str, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, target_ip, tIP_str, INET_ADDRSTRLEN);

    printf(" Sender IP: %s | Target IP: %s |", sIP_str, tIP_str);
    printf(" Sender MAC: %02X:%02X:%02X:%02X:%02X:%02X | Target MAC: %02X:%02X:%02X:%02X:%02X:%02X |", sender_mac[0], sender_mac[1], sender_mac[2], sender_mac[3], sender_mac[4], sender_mac[5], target_mac[0], target_mac[1], target_mac[2], target_mac[3], target_mac[4], target_mac[5]);

    u_short hardware_type = ntohs(arp_header->ar_hrd);
    u_short protocol_type = ntohs(arp_header->ar_pro);
    printf(" HW Type: %d | Proto Type: 0x%04X | HW Len: %u | Proto Len: %u\n", hardware_type, protocol_type, arp_header->ar_hln, arp_header->ar_hln);
}

void tcp_parsing(const struct pcap_pkthdr *h, const u_char *bytes, struct ether_header *etherHeader, int header_length){

    printf("L4 (TCP): ");
    struct tcphdr *tcp_header = (struct tcphdr *) (bytes + header_length);
    u_short src_port = ntohs(tcp_header->th_sport);
    u_short dst_port = ntohs(tcp_header->th_dport);

    printf("Src port: %d", src_port);

    if (src_port == 80) {
        printf(" (HTTP)");
    } else if (src_port == 443) {
        printf(" (HTTPS)");
    } else if (src_port == 53) {
        printf(" (DNS)");
    }

    printf(" |");

    printf("Dst port: %d", dst_port);

    if (dst_port == 80) {
        printf(" (HTTP)");
    } else if (dst_port == 443) {
        printf(" (HTTPS)");
    } else if (dst_port == 53) {
        printf(" (DNS)");
    }
    printf(" |");

    u_int tcp_seq_num = ntohl(tcp_header->th_seq);
    printf(" Seq: %u |", tcp_seq_num);

    u_int tcp_ack_num = ntohl(tcp_header->th_ack);
    printf(" Ack: %u |", tcp_ack_num);

    u_short tcp_win_size = tcp_header->th_win;
    printf(" Window size: %d |", tcp_win_size);

    u_int tcp_header_length = tcp_header->th_off * 4;
    printf(" Header Length: %d |", tcp_header_length);

    u_short tcp_checksum = tcp_header->th_sum;
    printf(" Checksum: 0x%02X |", tcp_checksum);

    u_char tcp_flags = tcp_header->th_flags;
    printf(" Flags: ");
    printf("[");
    if (tcp_flags & TH_SYN) {
        printf(" SYN ");
    }
    if (tcp_flags & TH_ACK) {
        printf(" ACK ");
    }
    if (tcp_flags & TH_FIN) {
        printf(" FIN ");
    }
    if (tcp_flags & TH_RST) {
        printf(" RST ");
    }
    if (tcp_flags & TH_PUSH) {
        printf(" PUSH ");
    }
    if (tcp_flags & TH_URG) {
        printf(" URG ");
    }
    printf("] |\n");

    printf("L7 (Payload): ");

    printf("Identified as ");
    if (dst_port == 80 || src_port == 80) {
        printf("HTTP on port 80");
    }
    else if (dst_port == 443 || src_port == 443) {
        printf("HTTPS/TLS on port 443");
    }
    else if (dst_port == 53 || src_port == 53) {
        printf("DNS on port 53");
    }
    else printf("UNKNOWN");

    header_length += tcp_header_length;
    int payload_len = h->len - header_length;
    printf(" - %d bytes\n", payload_len);

    int print_length = (payload_len> 64) ? 64 : payload_len;
    const u_char *payload = bytes + header_length;
    if (print_length > 0) {
        printf("Data (first %d bytes):\n", print_length);
        hex_dump(payload, print_length);
    }
}

void udp_parsing(const struct pcap_pkthdr *h, const u_char *bytes, struct ether_header *etherHeader, int header_length){
    printf("L4 (UDP):");

    struct udphdr *udp_header = (struct udphdr *)(bytes + header_length);

    u_short src_port = ntohs(udp_header->uh_sport);
    u_short dst_port = ntohs(udp_header->uh_dport);

    printf("Src port: %d", src_port);


    if (src_port == 80){
        printf(" (HTTP)");
    }
    else if (src_port == 443){
        printf(" (HTTPS)");
    }
    else if (src_port == 53){
        printf(" (DNS)");
    }
    printf(" |");

    printf("Dst port: %d", dst_port);
    if (dst_port == 80){
        printf(" (HTTP)");
    }
    else if (dst_port == 443){
        printf(" (HTTPS)");
    }
    else if (dst_port == 53){
        printf(" (DNS)");
    }
    printf(" |");

    u_short udp_header_length = ntohs(udp_header->uh_ulen);
    printf(" Length: %d |", udp_header_length);

    u_short udp_checksum = ntohs(udp_header->uh_sum);
    printf(" Checksum: 0x%04X |\n", udp_checksum);

    printf("L7 (Payload): ");

    printf("Identified as ");
    if (dst_port == 80 || src_port == 80){
        printf("HTTP on port 80");
    }
    else if (dst_port == 443 || src_port == 443){
        printf("HTTPS/TLS on port 443");
    }
    else if (dst_port == 53 || src_port == 53){
        printf("DNS on port 53");
    }
    else printf("UNKNOWN");

    header_length += udp_header_length;
    int payload_len = h->len - header_length;
    printf(" - %d bytes\n", payload_len);

    int print_length = (payload_len > 64) ? 64 : payload_len;
    const u_char *payload = bytes + header_length;
    if (print_length > 0) {
        printf("Data (first %d bytes):\n", print_length);
        hex_dump(payload, print_length);
    }

}