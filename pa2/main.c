#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <pcap/pcap.h>
#include <signal.h>
#include <stdint.h>


struct flow_info {
    uint32_t srcip;
    uint32_t dstip;
    uint16_t srcport;
    uint16_t dstport;
    int bytes;
    int pkts;
    int tcp_s;
    int tcp_r;
    struct flow_info *next_flow;
};

struct flow_info flow_head;

int bps, pps;
double tcp;
char *appname;

void print_statistics(int signum) {
    struct flow_info *flow_iterator;
    system("clear");
    printf("-----------------------DoS Detector------------------------\n");
    printf("%s", appname);
    if(bps != -1)
        printf(" -bps %d", bps);
    if(pps != -1)
        printf(" -pps %d", pps);
    if(tcp != -1.0)
        printf(" -tcp %f", tcp);
    printf("\n");
    for(flow_iterator = flow_head.next_flow; flow_iterator != NULL; flow_iterator = flow_iterator->next_flow) {
        printf("[%d.%d.%d.%d:%d] -> [%d.%d.%d.%d:%d]\n", (flow_iterator->srcip >> 24) & 0xff,
                                                         (flow_iterator->srcip >> 16) & 0xff,
                                                         (flow_iterator->srcip >> 8) & 0xff,
                                                         flow_iterator->srcip & 0xff,
                                                         flow_iterator->srcport,
                                                         (flow_iterator->dstip >> 24) & 0xff,
                                                         (flow_iterator->dstip >> 16) & 0xff,
                                                         (flow_iterator->dstip >> 8) & 0xff,
                                                         flow_iterator->dstip & 0xff,
                                                         flow_iterator->dstport);
        printf("History\n");
        
        printf("Real Time\n");
    }
    printf("-----------------------------------------------------------\n");
    alarm(1);
}

void usage(char* app) {
    fprintf(stderr, "Usage: %s [-bps bytes_per_second] [-pps packets_per_second] [-tcp failed_connection_ratio]\n", app);
}

int main(int argc, char **argv) {
    int i, opt;
    pcap_t *handle;
    char *interface;
    char errbuf[PCAP_ERRBUF_SIZE];
    uint8_t *packet;
    struct pcap_pkthdr header;
    struct sigaction sa;

    if(argc % 2 == 0) {
        usage(argv[0]);
        exit(-1);
    }

    pps = -1;
    bps = -1;
    tcp = -1.0;
    appname = (char*) malloc(strlen(argv[0])+1);
    strcpy(appname, argv[0]);

    errno = 0;
    for(i=1; i<argc; i+=2) {
        if(!strcmp(argv[i], "-bps")) {
            bps = strtol(argv[i+1], NULL, 10);
        }
        else if(!strcmp(argv[i], "-pps")) {
            pps = strtol(argv[i+1], NULL, 10);
        }
        else if(!strcmp(argv[i], "-tcp")) {
            tcp = strtod(argv[i+1], NULL);
        }
        else {
            usage(argv[0]);
            exit(-1);
        }
    }

    if(pps == -1 && bps == -1 && tcp == -1.0) {
        fprintf(stderr, "No detection guideline given: Detector terminated\n");
        exit(-1);
    }

    if((interface = pcap_lookupdev(errbuf)) == NULL) {
        fprintf(stderr, "pcap_lookupdev() failed: %s\n", errbuf);
        exit(-1);
    }

    if((handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf)) == NULL) {
        fprintf(stderr, "pcap_open_live() failed: %s\n", errbuf);
        exit(-1);
    }
    
    sa.sa_handler = &print_statistics;
    sa.sa_flags = SA_RESTART;
    sigaction(SIGALRM, &sa, NULL);
    alarm(1);
    while(1) {
        while((packet = pcap_next(handle, &header)) == NULL);
    }    

    return 0;
}
