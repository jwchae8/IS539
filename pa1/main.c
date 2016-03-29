#include <stdio.h>
#include <stdarg.h>
#include <stdint.h>
#include <pcap/pcap.h>

struct rule {
    /* ip header */
    uint8_t tos;
    uint16_t length;
    uint16_t fragment;
    uint8_t ttl;
    uint32_t srcip;
    uint32_t destip;
    
    /* tcp header */
    uint16_t srcport;
    uint16_t destport;
    uint32_t seq;
    uint32_t ack;
    uint8_t flag;

    /* tcp payload */
    char* http_request;
    char* content;
};

struct list_elem {
    struct rule element;
    struct list_elem *next;
};

int main(int argc, char **argv)
{
    int i, opt;
    char *interface, *rule_file;
    char *errbuf;
    pcap_t *handle;
    uint8_t *packet;
    struct pcap_pkthdr header;
    FILE *fp;
    char *rule_token;

    while((opt = getopt(argc, argv, "i:r:")) != -1) {
        switch(opt) {
            case 'i':
                interface = (char*)malloc(strlen(optarg)+1);
                strcpy(interface, optarg);
                break;
            case 'r':
                rule_file = (char*)malloc(strlen(optarg)+1);
                strcpy(rule_file, optarg);
                break;
            default:
                fprintf(stderr, "Usage: ./%s -i interface_name -r rule_file_name\n", argv[0]);
                exit(-1);
        }
    }

    if(interface == NULL || rule_file == NULL) {
        fprintf(stderr, "Usage: ./%s -i interface_name -r rule_file_name\n", argv[0]);
        exit(-1)
    }
    
    printf("IDS is running on %s and using rules written in %s\n", interface, rule_file);
    
    if((handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf)) == NULL) {
        fprintf(stderr, "[Error]Pcap initialization has failed on %s: %s\n", interface, errbuf);
        exit(-1);
    }

    if((fp = fopen(rule_file, "r")) == NULL) {
        fprintf(stderr, "[Error]File open error(file may not exist\n");
        exit(-1);
    }

    while((fscanf(fp, "%s", rule_token)) != EOF) {
        
    }

    while(true) {
        packet = pcap_next(handle, &header);
        
    }
    pcap_close(handle);
    return 0;
}
