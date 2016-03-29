#include <stdio.h>
#include <stdarg.h>
#include <stdint.h>
#include <pcap/pcap.h>

int main(int argc, char **argv)
{
    int i, opt;
    char *interface, *rule_file;
    char *errbuf;
    pcap_t *handle;
    uint8_t *packet;
    struct pcap_pkthdr header;
    FILE *fp;

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

    
    while(true) {
        packet = pcap_next(handle, &header);
        
    }
    pcap_close(handle);
    return 0;
}
