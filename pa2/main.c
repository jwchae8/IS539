#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <pcap/pcap.h>
#include <signal.h>
#include <stdint.h>



#define IP_VERSION(x) ((x >> 4) & 0x0f)
#define IP_HLENGTH(X) (X & 0x0f)
#define IP_FLAGS(X) ((X >> 5) & 0x07)
#define IP_FRAGOFFSET(X) (X & 0x1fff)
#define TCP_DATAOFFSET(x) ((x >> 4) & 0x0f)


struct flow_history {
    int bytes;
    int bi_bytes;
    int pkts;
    int bi_pkts;
    int tcp_s;
    int tcp_f;
    struct flow_history *next_history;
};

struct flow_info {
    uint32_t srcip;
    uint32_t dstip;
    uint16_t srcport;
    uint16_t dstport;
    uint8_t flag;
    int bytes;
    int bi_bytes;
    int pkts;
    int bi_pkts;
    int tcp_s;
    int tcp_f;
    int tot_bytes;
    int tot_bi_bytes;
    int tot_pkts;
    int tot_bi_pkts;
    int tot_tcp_s;
    int tot_tcp_f;
    int start_time;
    int syn_time;
    struct flow_info *next_flow;
    struct flow_history *history;
};


struct flow_info flow_head;

int bps, pps;
double tcp;
char *appname;
int seconds;

void print_statistics(int signum) {
    struct flow_info *flow_iterator;
    struct flow_history *history_iterator, *new_history;
    int order, report;
    char err[50] = "";
    signal(SIGALRM, print_statistics);
    seconds++;
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
        order = 0;
        for(history_iterator = flow_iterator->history; history_iterator != NULL; history_iterator = history_iterator->next_history) {
            printf("[%ds : %ds] : [BPS : %d, BI_DIRECTION_BPS : %d], [PPS : %d, BI_DIRECTION_PPS : %d], [TCP_S : %d], [TCP_F : %d], [TCP_R : %f]", flow_iterator->start_time + order * 60
                                                                                                                                                 , flow_iterator->start_time + (order + 1) * 60
                                                                                                                                                 , history_iterator->bytes
                                                                                                                                                 , history_iterator->bi_bytes
                                                                                                                                                 , history_iterator->pkts
                                                                                                                                                 , history_iterator->bi_pkts
                                                                                                                                                 , history_iterator->tcp_s
                                                                                                                                                 , history_iterator->tcp_f
                                                                                                                                                 , (double)history_iterator->tcp_f / history_iterator->tcp_s);
            report = 0;
            err[0] = 0;
            if(bps != -1 && history_iterator->bytes > bps) {
                strcat(err, " BPS");
                report = 1;
            }
            if(pps != -1 && history_iterator->pkts > pps) {
                if(!report) {
                    strcat(err, " PPS");
                    report = 1;
                }
                else {
                    strcat(err, " ,PPS");
                }
            }
            if(tcp != -1.0 && (double)history_iterator->tcp_f > (double)history_iterator->tcp_s * tcp) {
                if(!report) {
                    strcat(err, " TCP");
                    report = 1;
                }
                else {
                    strcat(err, " ,TCP");
                }
            }
            if(report) {
                printf("[Alert: %s]", err);
            }
            printf("\n");
            order++;
        }
        printf("Real Time\n");
	if((flow_iterator->flag == 0x02 || flow_iterator->flag == 0x12) && seconds - flow_iterator->syn_time >= 30) {
	    flow_iterator->flag = 0;
	    flow_iterator->tcp_f += 1;
	}
        printf("              [BPS : %d, BI_DIRECTION_BPS : %d], [PPS : %d, BI_DIRECTION_PPS : %d], [TCP_S : %d], [TCP_F : %d], [TCP_R : %f]", flow_iterator->bytes
                                                                                                                                             , flow_iterator->bi_bytes
                                                                                                                                             , flow_iterator->pkts
                                                                                                                                             , flow_iterator->bi_pkts
                                                                                                                                             , flow_iterator->tcp_s
                                                                                                                                             , flow_iterator->tcp_f
                                                                                                                                             , (double)flow_iterator->tcp_f / flow_iterator->tcp_s);
            report = 0;
            err[0] = 0;
            if(bps != -1 && flow_iterator->bytes > bps) {
                strcat(err, " BPS");
                report = 1;
            }
            if(pps != -1 && flow_iterator->pkts > pps) {
                if(!report) {
                    strcat(err, " PPS");
                    report = 1;
                }
                else {
                    strcat(err, " ,PPS");
                }
            }
            if(tcp != -1.0 && (double)flow_iterator->tcp_f > (double) flow_iterator->tcp_s * tcp) {
                if(!report) {
                    strcat(err, " TCP");
                    report = 1;
                }
                else {
                    strcat(err, " ,TCP");
                }
            }
            if(report) {
                printf("[Alert: %s]", err);
            }
            printf("\n");
        flow_iterator->tot_bytes += flow_iterator->bytes;
        flow_iterator->tot_bi_bytes += flow_iterator->bi_bytes;
        flow_iterator->tot_pkts += flow_iterator->pkts;
        flow_iterator->tot_bi_pkts += flow_iterator->bi_pkts;
        flow_iterator->tot_tcp_s += flow_iterator->tcp_s;
        flow_iterator->tot_tcp_f += flow_iterator->tcp_f;
        flow_iterator->bytes = 0;
        flow_iterator->bi_bytes = 0;
        flow_iterator->pkts = 0;
        flow_iterator->bi_pkts = 0;
        flow_iterator->tcp_s = 0;
        flow_iterator->tcp_f = 0;
        if((seconds-flow_iterator->start_time) % 60 == 0) {
            new_history = (struct flow_history *) malloc(sizeof(struct flow_history));
            memset(new_history, 0, sizeof(struct flow_history));
            new_history->bytes = flow_iterator->tot_bytes / 60;
            new_history->bi_bytes = flow_iterator->tot_bi_bytes / 60;
            new_history->pkts = flow_iterator->tot_pkts / 60;
            new_history->bi_pkts = flow_iterator->tot_bi_pkts / 60;
            new_history->tcp_s = flow_iterator->tcp_s / 60;
            new_history->tcp_f = flow_iterator->tcp_f / 60;
            new_history->next_history = NULL;
            if(flow_iterator->history == NULL) {
                flow_iterator->history = new_history;
            }
            else {
                history_iterator = flow_iterator->history;
                while(history_iterator->next_history != NULL) {
                    history_iterator = history_iterator->next_history;
                }
                history_iterator->next_history = new_history;
            }
            flow_iterator->tot_bytes = 0;
            flow_iterator->tot_bi_bytes = 0;
            flow_iterator->tot_pkts = 0;
            flow_iterator->tot_bi_pkts = 0;
            flow_iterator->tot_tcp_s = 0;
            flow_iterator->tot_tcp_f = 0;
        }
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
    uint8_t *packet, *ip, *tcphdr, tmp_flag;
    uint32_t srcip, dstip;
    uint16_t srcport, dstport;
    struct pcap_pkthdr header;
    struct sigaction sa;
    struct flow_info *flow_iterator, *new_flow, *same, *opposite;

    if(argc % 2 == 0) {
        usage(argv[0]);
        exit(-1);
    }

    pps = -1;
    bps = -1;
    tcp = -1.0;
    appname = (char*) malloc(strlen(argv[0])+1);
    strcpy(appname, argv[0]);
    flow_head.next_flow = NULL;

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
    
    //sa.sa_handler = &print_statistics;
    //sigemptyset(&sa.sa_mask);
    //sa.sa_flags = 0;
    //sigaction(SIGALRM, &sa, NULL);
    signal(SIGALRM, print_statistics);
    seconds=0;
    alarm(1);
    while(1) {
        packet = pcap_next(handle, &header);
	if(packet == NULL) continue;
        ip = packet + 14;
        if(*(uint8_t*)(ip+9) == 6 || *(uint8_t*)(ip+9) == 17) {
            tcphdr = ip + 4 * IP_HLENGTH(*(uint8_t*)(ip));
            srcip = ntohl(*(uint32_t*)(ip+12));
            dstip = ntohl(*(uint32_t*)(ip+16));
            srcport = ntohs(*(uint16_t*)(tcphdr));
            dstport = ntohs(*(uint16_t*)(tcphdr+2));
            flow_iterator = flow_head.next_flow;
            same = NULL;
            opposite = NULL;
            while(flow_iterator != NULL) { 
                if(flow_iterator->srcip == srcip && flow_iterator->dstip == dstip && flow_iterator->srcport == srcport && flow_iterator->dstport == dstport) {
                    same = flow_iterator;
                    if(opposite != NULL)
                        break;
                }
                if(flow_iterator->srcip == dstip && flow_iterator->dstip == srcip && flow_iterator->srcport == dstport && flow_iterator->dstport == srcport) {
                    opposite = flow_iterator;
                    if(same != NULL)
                        break;
                }
		flow_iterator = flow_iterator->next_flow;
            }
            if(same == NULL) {
                new_flow = (struct flow_info *) malloc(sizeof(struct flow_info));
                memset(new_flow, 0, sizeof(struct flow_info));
                new_flow->start_time = seconds;
                new_flow->bytes = ntohs(*(uint16_t*)(ip+2)) + 14;
                new_flow->bi_bytes = ntohs(*(uint16_t*)(ip+2)) + 14;
                new_flow->pkts = 1;
                new_flow->bi_pkts = 1;
                new_flow->tcp_s = 0;
                new_flow->tcp_f = 0;
		new_flow->srcip = srcip;
		new_flow->dstip = dstip;
		new_flow->srcport = srcport;
		new_flow->dstport = dstport;
                new_flow->history = NULL;
                new_flow->next_flow = NULL;
		if(*(uint8_t*)(ip+9) == 6)  {
		    new_flow->flag = *(uint8_t*)(tcphdr+13);
		    if(new_flow->flag == 0x02){
		        new_flow->syn_time = seconds;
		    }
		    else {
			new_flow->flag = 0;
			new_flow->tcp_f = 1;
		    }
		}
                flow_iterator = flow_head.next_flow;
                if(flow_iterator == NULL) {
                    flow_head.next_flow = new_flow;
                }
                else {
                    while(flow_iterator->next_flow != NULL) {
                        flow_iterator = flow_iterator->next_flow;
                    }
                    flow_iterator->next_flow = new_flow;
                }
            }
            else {
                same->bytes += ntohs(*(uint16_t*)(ip+2)) + 14;
                same->bi_bytes += ntohs(*(uint16_t*)(ip+2)) + 14;
                same->pkts += 1;
                same->bi_pkts += 1;
		if(*(uint8_t*)(ip+9) == 6) {
		    tmp_flag = *(uint8_t*)(tcphdr+13);
		    if(opposite->flag == 0x02 && tmp_flag == 0x12) {
			same->flag = tmp_flag;
		    }
		    else if(opposite->flag == 0x12 && tmp_flag == 0x10) {
			same->flag = tmp_flag;
			opposite->flag = tmp_flag;
			same->tcp_s += 1;
			opposite->tcp_s += 1;
		    }
		    else if(opposite->flag == 0x10 && tmp_flag == 0x01) {
			same->flag = tmp_flag;
		    }
		    else if(same->flag == 0x01 && tmp_flag == 0x10) {
			same->flag = 0x11;
		    }
		    else if((same->flag == 0x11 || same->flag == 0) && tmp_flag == 0x02) {
			same->flag = 0x02;
			same->syn_time = seconds;
		    }
		    else {
			same->flag = 0;
			same->tcp_f += 1;
		    }
		}
            }
            if(opposite == NULL) {
                new_flow = (struct flow_info *) malloc(sizeof(struct flow_info));
                memset(new_flow, 0, sizeof(struct flow_info));
                new_flow->start_time = seconds;
                new_flow->bi_bytes = ntohs(*(uint16_t*)(ip+2)) + 14;
                new_flow->bi_pkts = 1;
                new_flow->tcp_s = 0;
                new_flow->tcp_f = 0;
		new_flow->srcip = dstip;
		new_flow->dstip = srcip;
		new_flow->srcport = dstport;
		new_flow->dstport = srcport;
                new_flow->history = NULL;
                new_flow->next_flow = NULL;
		if(*(uint8_t*)(ip+9) == 6)  {
		    tmp_flag = *(uint8_t*)(tcphdr+13);
		    if(tmp_flag == 0x02){
		        new_flow->syn_time = seconds;
		    }
		    else {
			new_flow->flag = 0;
			new_flow->tcp_f = 1;
		    }
		}
                flow_iterator = flow_head.next_flow;
                if(flow_iterator == NULL) {
                    flow_head.next_flow = new_flow;
                }
                else {
                    while(flow_iterator->next_flow != NULL) {
                        flow_iterator = flow_iterator->next_flow;
                    }
                    flow_iterator->next_flow = new_flow;
                }
            }
            else {
                opposite->bi_bytes += ntohs(*(uint16_t*)(ip+2)) + 14;
                opposite->bi_pkts += 1;
            }
        }
    }    

    return 0;
}
