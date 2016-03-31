#include <stdio.h>
#include <stdarg.h>
#include <stdint.h>
#include <ctype.h>
#include <string.h>
#include <pcap/pcap.h>


#define PORT_MAX 65535
#define PORT_MIN 0


int is_ip(char* ipstr, uint32_t* ipnum) {
    int i, dot_count = 0;
    uint32_t ip_a, ip_b, ip_c, ip_d;
    if(strcmp(ipstr, "any")) {
        for(i=0; i<strlen(ipstr); i++) {
            if(ipstr[i] == '.') {
                dot_count++;
            }
            else if(!isdigit(ipstr[i])) {
                return -1;
            }
        }
        if(dot_count != 3) {
            return -1;
        }
        sscanf(ipstr, "%d.%d.%d.%d", &ip_a, &ip_b, &ip_c, &ip_d);
        if(ip_a > 255 || ip_b > 255 || ip_c > 255 || ip_d > 255) {
            return -1;
        }
        *ipnum = ip_a << 24 + ip_b << 16 + ip_c << 8 + ip_d;
    }
    else {
        *ipnum = 0;
    }
    return 0;
}

int is_port(char* portstr, uint16_t* portnum) {
    int i, tmp;
    if(strcmp(portstr, "any")) {
        for(i=0; i<strlen(portstr); i++) {
            if(!isdigit(portstr[i])) {
                return -1;
            }
        }
        tmp = atoi(portstr);
        if(tmp > PORT_MAX) {
            return -1;
        }
        *portnum = (uint16_t) tmp;
    }
    else {
        *portnum = 0;
    }
    return 0;
}


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
    int i, opt, ret;
    char *interface, *rule_file;
    char *errbuf;
    pcap_t *handle;
    uint8_t *packet;
    struct pcap_pkthdr header;
    FILE *fp;
    char rule_token[10], iptoken[4][5];
    struct rule* new_rule;
    struct list_elem* rule_list;
    int pattern_rule_exists;

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
    pattern_rule_exists = 1;
    while((fscanf(fp, "%s", rule_token)) != EOF) {
        new_rule = (struct rule*) malloc(sizeof(struct rule));
        if(pattern_rule_exists) {
            if(strcmp(rule_token, "alert")) {
                fprintf(stderr, "[Error]Undefined action : action of rule must be \'alert\'\nor this is one of unread tokens of wrong rule: given token = %s\n", rule_token);
                continue;
            }
            fscanf(fp, "%s", rule_token);
        }
        if(strcmp(rule_token, "tcp")) {
            fprintf(stderr, "[Error]Undefined protocol : protocol of rule must be \'tcp\': given token = %s\n", rule_token);
            continue;
        }
        fscanf(fp, "%s", rule_token);
        if((ret = is_ip(rule_token, &(new_rule->srcip))) < 0) {
            fprintf(stderr, "[Error]Not valid ip number : given token = %s\n", rule_token);
            continue;
        }
        fscanf(fp, "%s", rule_token);
        if((ret = is_port(rule_token, &(new_rule->srcport))) < 0) {
            fprintf(stderr, "[Error]Not valid port number : given token = %s\n", rule_token);
            continue;
        }
        fscanf(fp, "%s", rule_token);
        if(strcmp(rule_token, "->")) {
            fprintf(stderr, "[Error]Not correct format : this rule lacks directional mark: given token = %s\n", rule_token);
        }
        fscanf(fp, "%s", rule_token);
        if((ret = is_ip(rule_token, &(new_rule->destip))) < 0) {
            fprintf(stderr, "[Error]Not valid ip number : given token = %s\n", rule_token);
            continue;
        }
        fscanf(fp, "%s", rule_token);
        if((ret = is_port(rule_token, &(new_rule->destport))) < 0) {
            fprintf(stderr, "[Error]Not valid port number : given token = %s\n", rule_token);
            continue;
        }
        fscanf(fp, "%s", rule_token);
        if(!strcmp(rule_token, "alert")) {
            pattern_rule_exists = 0;
            continue;
        }
        pattern_rule_exists = 1;
        while(true){
            if(rule_token[0] == '(') {
                rule_token++;
            }
            if(strstr(rule_token, ";)")) {
                break;
            }
            fscanf(fp, "%s", rule_token);
        }
    }
    fclose(fp);
    while(true) {
        packet = pcap_next(handle, &header);
        
    }
    pcap_close(handle);
    return 0;
}
