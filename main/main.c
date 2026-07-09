#include "include/functions.h"
#include "include/handler_filter.h"
pcap_t *sig_handle = NULL;

int main(){
    signal(SIGINT, signalHandler);

    char *device;
    pcap_if_t *d;
    char error_buffer[PCAP_ERRBUF_SIZE];

    pcap_t *handle;
    device_handler(device, d, handle, error_buffer);

    return 0;

//    return_code = pcap_lookupnet(device, &ip_raw, &subnet_mask_raw, error_buffer); -> Depreciated :(
//    if (return_code == -1){
//        printf("Error (lookupnet): %s\n", error_buffer);
//        return 1;
//    }
//
//    address.s_addr = ip_raw;
//    strcpy(ip, inet_ntoa(address));
//    if (!ip){
//        printf("Error inet_ntoa ip: %s\n", error_buffer);
//        return 1;
//    }
//
//
//    address.s_addr = subnet_mask_raw;
//    strcpy(subnet_mask, inet_ntoa(address));
//    if (!subnet_mask){
//        printf("Error inet_ntoa subnet: %s\n", error_buffer);
//        return 1;
//    } -> Doesnt work well.

}
