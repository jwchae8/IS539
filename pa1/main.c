#include <stdio.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>
#include <string.h>
#include <malloc.h>
#include <pcap/pcap.h>
#include <arpa/inet.h>


#define PORT_MAX 65535
#define PORT_MIN 0

#define ETHERNET_SIZE 14
#define BUFLEN 2048

#define IP_VERSION(X) ((X >> 4) & 0x0f)
#define IP_HLENGTH(X) (X & 0x0f)
#define IP_FLAGS(X) ((X >> 5) & 0x07)
#define IP_FRAGOFFSET(X) (X & 0x1fff)

struct rule {
    /* Don't Care/ Care bit */
    uint16_t care;

    /* ip header */
    uint8_t tos;
    uint16_t length;
    uint16_t fragoffset;
    uint8_t ttl;
    uint32_t srcip;
    uint32_t destip;

    /* tcp header */
    uint16_t srcport;
    uint16_t destport;
    uint32_t seq;
    uint32_t ack;
    uint8_t flags;

    /* tcp payload */
    unsigned char* http_request;
    unsigned char* content;

    /* next rule */
    struct rule *next_rule;
};



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
        if(ip_a > UINT8_MAX || ip_b > UINT8_MAX || ip_c > UINT8_MAX || ip_d > UINT8_MAX) {
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

int process_8bit(char* str, uint8_t* num) {
    int i, ret;
    for(i=0; str[i] != ';'; i++) {
        if(!isdigit(str[i]) || i == 3) {
            return -1;
        }
    }
    ret = atoi(str);
    if(ret > UINT8_MAX) {
        return -1;
    }
    *num = (uint8_t) ret;
    return 0;
}

int process_16bit(char* str, uint16_t* num) {
    int i, ret;
    for(i=0; str[i] != ';'; i++) {
        if(!isdigit(str[i]) || i == 5) {
            return -1;
        }
    }
    ret = atoi(str);
    if(ret > UINT16_MAX) {
        return -1;
    }
    *num = (uint16_t) ret;
    return 0;
}

int process_32bit(char* str, uint32_t* num) {
    int i;
    uint32_t ret = 0;
    for(i=0; str[i] != ';'; i++) {
        if(!isdigit(str[i]) || i == 10) {
            return -1;
        }
        if(ret > UINT32_MAX / 10 || (ret == UINT32_MAX / 10 && str[i] > '5')) {
            return -1;
        }
        ret = ret * 10 + str[i] - '0';
    }
    if(ret > UINT32_MAX) {
        return -1;
    }
    *num = (uint8_t) ret;
    return 0;
}

void insert_rule(struct rule *head, struct rule *new_rule) {
    struct rule *iterator = head;
    while(iterator->next_rule != NULL) {
        iterator = iterator->next_rule;
    }
    iterator->next_rule = new_rule;
}



int main(int argc, char **argv)
{
    int i, opt, error, is_attack;
    char *interface, *rule_file;
    char *errbuf;
    pcap_t *handle;
    uint8_t *packet, *ip, *tcp, tcp_flags, *http;
    struct pcap_pkthdr header;
    FILE *fp;
    char rule_token[BUFLEN];
    char field[20], *colon, *semicolon, *lquote, *rquote;
    struct rule* new_rule, *rule_iterator;
    struct rule head;
    int pattern_rule_exists, pattern_completed;
    int rule_count = 0;

    while((opt = getopt(argc, argv, "i:r:")) != -1) {
        switch(opt) {
            case 'i':
                interface = (char*)malloc(strlen(optarg)+1);
                strcpy(interface, optarg);
                interface[strlen(optarg)] = 0;
                break;
            case 'r':
                rule_file = (char*)malloc(strlen(optarg)+1);
                strcpy(rule_file, optarg);
                rule_file[strlen(optarg)] = 0;
                break;
            default:
                fprintf(stderr, "Usage: ./%s -i interface_name -r rule_file_name\n", argv[0]);
                exit(-1);
        }
    }

    if(interface == NULL || rule_file == NULL) {
        fprintf(stderr, "Usage: ./%s -i interface_name -r rule_file_name\n", argv[0]);
        exit(-1);
    }

    printf("IDS is running on %s and using rules written in %s\n", interface, rule_file);

    if((handle = pcap_open_live(interface, BUFSIZ, 0, 2000, errbuf)) == NULL) {
        fprintf(stderr, "[Error]Pcap initialization has failed on %s: %s\n", interface, errbuf);
        exit(-1);
    }

    /*    if((handle = pcap_create(interface, errbuf)) == NULL) {
          fprintf(stderr, "[Error]Pcap initialization has failed on %s: %s\n", interface, errbuf);
          exit(-1);
          }

          if(pcap_activate(handle)) {
          fprintf(stderr, "[Error]Pcap activation has failed on %s: %s\n", interface, errbuf);
          exit(-1);
          }*/
    if((fp = fopen(rule_file, "r")) == NULL) {
        fprintf(stderr, "[Error]File open error(file may not exist\n");
        exit(-1);
    }
    pattern_rule_exists = 1;
    while((fscanf(fp, "%s", rule_token)) != EOF) {
        error = 0;
        new_rule = (struct rule*) malloc(sizeof(struct rule));
        memset(new_rule, 0, sizeof(struct rule));
        if(pattern_rule_exists) {
            if(strcmp(rule_token, "alert")) {
                fprintf(stderr, "[Error]Undefined action : action of rule must be \'alert\'\nor this is one of unread tokens of wrong rule: given token = %s\n", rule_token);
                continue;
            }
            fscanf(fp, "%s", rule_token);
        }
        if(strcmp(rule_token, "tcp")) {
            fprintf(stderr, "[Error]Undefined protocol : protocol of rule must be \'tcp\': given token = %s\n", rule_token);
            free(new_rule);
            continue;
        }
        fscanf(fp, "%s", rule_token);
        if(is_ip(rule_token, &(new_rule->srcip)) < 0) {
            fprintf(stderr, "[Error]Not valid ip number : given token = %s\n", rule_token);
            free(new_rule);
            continue;
        }
        if(new_rule->srcip != 0) {
            new_rule->care += 1 << 4;
        }
        fscanf(fp, "%s", rule_token);
        if(is_port(rule_token, &(new_rule->srcport)) < 0) {
            fprintf(stderr, "[Error]Not valid port number : given token = %s\n", rule_token);
            free(new_rule);
            continue;
        }
        if(new_rule->srcport != 0) {
            new_rule->care += 1 << 6;
        }
        fscanf(fp, "%s", rule_token);
        if(strcmp(rule_token, "->")) {
            fprintf(stderr, "[Error]Not correct format : this rule lacks directional mark: given token = %s\n", rule_token);
            free(new_rule);
            continue;
        }
        fscanf(fp, "%s", rule_token);
        if(is_ip(rule_token, &(new_rule->destip)) < 0) {
            fprintf(stderr, "[Error]Not valid ip number : given token = %s\n", rule_token);
            free(new_rule);
            continue;
        }
        if(new_rule->destip != 0) {
            new_rule->care += 1 << 5;
        }
        fscanf(fp, "%s", rule_token);
        if(is_port(rule_token, &(new_rule->destport)) < 0) {
            fprintf(stderr, "[Error]Not valid port number : given token = %s\n", rule_token);
            free(new_rule);
            continue;
        }
        if(new_rule->destport != 0) {
            new_rule->care += 1 << 7;
        }
        fscanf(fp, "%s", rule_token);
        if(!strcmp(rule_token, "alert")) {
            pattern_rule_exists = 0;
            continue;
        }
        pattern_rule_exists = 1;
        pattern_completed = 0;
        if(rule_token[0] != '(') {
            fprintf(stderr, "[Error]Not valid pattern rule - it should be surrounded with ( and ) : given token = %s\n", rule_token);
            free(new_rule);
            continue;
        }
        do{
            if((colon = strchr(rule_token, ':')) == NULL) {
                fprintf(stderr, "[Error]Not valid pattern rule - no colon : given token = %s\n", rule_token);
                free(new_rule);
                break;
            }
            if((semicolon = strchr(rule_token, ';')) == NULL) {
                fprintf(stderr, "[Error]Not valid pattern rule - no semicolon : given token = %s\n", rule_token);
                free(new_rule);
                break;
            }
            strncpy(field, rule_token + (rule_token[0] == '(' ? 1 : 0), colon - rule_token - (rule_token[0] == '(' ? 1 : 0));
            field[colon - rule_token - (rule_token[0] == '(' ? 1 : 0)] = 0;
            printf("parsed field name : %s\n", field);
            if(!strcmp(field, "tos")) {
                if(process_8bit(colon+1, &(new_rule->tos)) < 0) {
                    fprintf(stderr, "[Error]Not valid pattern rule - invalid tos value : given token = %s\n", rule_token);
                    free(new_rule);
                    break;
                }
                new_rule->care += 1;
            }
            else if(!strcmp(field, "length")) {
                if(process_16bit(colon+1, &(new_rule->length)) < 0) {
                    fprintf(stderr, "[Error]Not valid pattern rule - invalid length value : given token = %s\n", rule_token);
                    free(new_rule);
                    break;
                }
                new_rule->care += 1 << 1;
            }
            else if(!strcmp(field, "fragoffset")) {
                if(process_16bit(colon+1, &(new_rule->fragoffset)) < 0) {
                    fprintf(stderr, "[Error]Not valid pattern rule - invalid tos value : given token = %s\n", rule_token);
                    free(new_rule);
                    break;
                }
                new_rule->care += 1 << 2;
            }
            else if(!strcmp(field, "ttl")) { 
                if(process_8bit(colon+1, &(new_rule->ttl)) < 0) {
                    fprintf(stderr, "[Error]Not valid pattern rule - invalid ttl value : given token = %s\n", rule_token);
                    free(new_rule);
                    break;
                }
                new_rule->care += 1 << 3;
            }
            else if(!strcmp(field, "seq")) {
                if(process_32bit(colon+1, &(new_rule->seq)) < 0) {
                    fprintf(stderr, "[Error]Not valid pattern rule - invalid seq value : given token = %s\n", rule_token);
                    free(new_rule);
                    break;
                }
                new_rule->care += 1 << 8;
            }
            else if(!strcmp(field, "ack")) {
                if(process_32bit(colon+1, &(new_rule->ack)) < 0) {
                    fprintf(stderr, "[Error]Not valid pattern rule - invalid ack value : given token = %s\n", rule_token);
                    free(new_rule);
                    break;
                }
                new_rule->care += 1 << 9;
            }
            else if(!strcmp(field, "flags")) {
                for(i=1; colon[i] != ';' ; i++) {
                    if(colon[i] == 'F') {
                        new_rule->flags += 1;
                    }
                    else if(colon[i] == 'S') {
                        new_rule->flags += 1 << 1;
                    }
                    else if(colon[i] == 'R') {
                        new_rule->flags += 1 << 2;
                    }
                    else if(colon[i] == 'P') {
                        new_rule->flags += 1 << 3;
                    }
                    else if(colon[i] == 'A') {
                        new_rule->flags += 1 << 4;
                    }
                    else if(colon[i] == 'U') {
                        new_rule->flags += 1 << 5;
                    }
                    else if(colon[i] == 'C') {
                        new_rule->flags += 1 << 6;
                    }
                    else if(colon[i] == 'E') {
                        new_rule->flags += 1 << 7;
                    }
                    else {
                        free(new_rule);
                        error = 1;
                        break;
                    }
                }
                if(error) {
                    fprintf(stderr, "[Error]Not valid pattern rule - No such flag bit exists : given token =%s\n", rule_token);
                    break;
                }
                new_rule->care += 1 << 10;
            }
            else if(!strcmp(field, "http_request") || !strcmp(field, "content")) {
                lquote = colon + 1;
                if(lquote[0] != '\"') {
                    fprintf(stderr, "[Error]Not valid pattern rule - value should be surrounded with \"s : given token = %s\n", rule_token);
                    break;
                }
                if((rquote = strrchr(rule_token, '\"')) == NULL) {
                    fprintf(stderr, "[Error]Not valid pattern rule - value should be surrounded with \"s : given token = %s\n", rule_token);
                    break;
                }
                if(lquote == rquote) {
                    fprintf(stderr, "[Error]Not valid pattern rule - value should be surrounded with \"s : given token = %s\n", rule_token);
                    break;
                }
                if(lquote + 1 == rquote) {
                    fprintf(stderr, "[Error]Not valid pattern rule - empty value : given token = %s\n", rule_token);
                    break;
                }
                if(!strcmp(field, "http_request")) {
                    new_rule->http_request = (unsigned char*) malloc(sizeof(unsigned char) * (rquote - lquote) + 1);
                    strncpy(new_rule->http_request, lquote+1, rquote - lquote);
                    new_rule->http_request[rquote - lquote] = 0;
                    new_rule->care += 1 << 11;
                }
                else {
                    new_rule->content = (unsigned char*) malloc(sizeof(unsigned char) * (rquote - lquote) + 1);
                    strncpy(new_rule->content, lquote+1, rquote - lquote);
                    new_rule->content[rquote - lquote] = 0;
                    new_rule->care += 1 << 12;
                }
            }
            else {
                fprintf(stderr, "[Error]Not valid pattern rule - No such field for pattern rule : given token = %s\n", rule_token);
                break;
            }
            if(strstr(rule_token, ")")) {
                pattern_completed = 1;
                break;
            }
        }while(fscanf(fp, "%s", rule_token)!=EOF);
        if(pattern_completed) {
            insert_rule(&head, new_rule);
            rule_count++;
            continue;
        }
        if(colon != NULL) {
            fprintf(stderr, "[Error]Not valid pattern rule - miscellaneous : given token = %s\n", rule_token);
        }
    }
    fclose(fp);

    printf("From %s, IDS program added %d rules.\nNow it begins to investigate packets.\n", rule_file, rule_count);
    while(1) {
        while((packet = pcap_next(handle, &header)) == NULL);
        rule_iterator = head.next_rule;
        is_attack = 0;
        ip = packet + ETHERNET_SIZE;
        tcp = ip + 4*IP_HLENGTH(*(uint8_t*)(ip));
        http = tcp + 4*(*(uint8_t*)(tcp+12));
        while((rule_iterator = rule_iterator->next_rule) != NULL) {
            if(rule_iterator->care & 0x1 && rule_iterator->tos != ntohs(*(uint8_t*)(ip+1))) {
                continue;
            }
            if(rule_iterator->care & 0x2 && rule_iterator->length != ntohs(*(uint16_t*)(ip+2))) {
                continue;
            }
            if(rule_iterator->care & 0x4 && rule_iterator->fragoffset != ntohs(*(uint16_t*)(ip+4))) {
                continue;
            }
            if(rule_iterator->care & 0x8 && rule_iterator->ttl != *(uint8_t*)(ip+8)) {
                continue;
            }
            if(rule_iterator->care & 0x100 && rule_iterator->seq != ntohl(*(uint32_t*)(tcp+4))) {
                continue;
            }
            if(rule_iterator->care & 0x200 && rule_iterator->ack != ntohl(*(uint32_t*)(tcp+8))) {
                continue;
            }
            if(rule_iterator->care & 0x400 && rule_iterator->flags != *(uint8_t*)(tcp+13)) {
                continue;
            }
            if(rule_iterator->care & 0x10 && rule_iterator->srcip != ntohl(*(uint32_t*)(ip+12))) {
                continue;
            }
            if(rule_iterator->care & 0x20 && rule_iterator->destip != ntohl(*(uint32_t*)(ip+16))) {
                continue;
            }
            if(rule_iterator->care & 0x40 && rule_iterator->srcport != ntohs(*(uint16_t*)tcp)) {
                continue;
            }
            if(rule_iterator->care & 0x80 && rule_iterator->destport != ntohs(*(uint16_t*)(tcp+2))) {
                continue;
            }
            /*if(rule_iterator->care & 0x800 && strcmp(rule_iterator->http_request, header)) {
                continue;
            }
            if(rule_iterator->care & 0x1000 && strcmp(rule_iterator->content, payload)) {
                continue;   
            }*/
            is_attack = 1;
            break;
        }
        printf("IP header\n");
        printf("  Version: %d\n", IP_VERSION(*(uint8_t*)(ip)));
        printf("  Header Length: %d\n", IP_HLENGTH(*(uint8_t*)(ip)));
        printf("  Type of Service: %d\n", ntohs(*(uint8_t*)(ip+1)));
        printf("  Total Length: %d\n", ntohs(*(uint16_t*)(ip+2)));
        printf("  Identification: %d\n", ntohs(*(uint16_t*)(ip+4)));
        printf("  Flags: %d\n",  IP_FLAGS(*(uint8_t*)(ip+6)));
        printf("  Fragment Offset: %d\n", IP_FRAGOFFSET(ntohs(*(uint16_t*)(ip+6))));
        printf("  TTL: %d\n", *(uint8_t*)(ip+8));
        printf("  Protocol: %d\n", *(uint8_t*)(ip+9));
        printf("  Header Checksum: %d\n", ntohs(*(uint16_t*)(ip+10)));
        printf("  Source IP Address: %d.%d.%d.%d\n", *(uint8_t*)(ip+12), 
                *(uint8_t*)(ip+13), 
                *(uint8_t*)(ip+14), 
                *(uint8_t*)(ip+15));
        printf("  Destination IP Address: %d.%d.%d.%d\n\n\n", *(uint8_t*)(ip+16), 
                *(uint8_t*)(ip+17), 
                *(uint8_t*)(ip+18), 
                *(uint8_t*)(ip+19));
        printf("TCP header\n");
        printf("  Source Port: %d\n", ntohs(*(uint16_t*)tcp));
        printf("  Destination Port: %d\n", ntohs(*(uint16_t*)(tcp+2)));
        printf("  Sequence Number: %u\n", *(uint32_t*)(tcp+4));
        printf("  Acknowledgment Number: %u\n", *(uint32_t*)(tcp+8));
        printf("  Data Offset: %d\n", *(uint8_t*)(tcp+12));
        tcp_flags = *(uint8_t*)(tcp + 13);
        printf("  Flags C: %d, E: %d, U: %d, A: %d, P: %d, R: %d, S: %d, F: %d\n", (tcp_flags & 0x80) >> 7, 
                (tcp_flags & 0x40) >> 6, 
                (tcp_flags & 0x20) >> 5, 
                (tcp_flags & 0x10) >> 4, 
                (tcp_flags & 0x08) >> 3, 
                (tcp_flags & 0x04) >> 2, 
                (tcp_flags & 0x02) >> 1, 
                tcp_flags & 0x01);
        printf("  Window Size: %d\n", ntohs(*(uint16_t*)(tcp+14)));
        printf("  Checksum: %d\n", ntohs(*(uint16_t*)(tcp+16)));
        printf("  Urgent Pointer: %d\n\n\n", ntohs(*(uint16_t*)(tcp+18)));
        printf("  Payload:\n");
	for(i=0; i<strlen(http); i++) {
	    if(i % 16 == 0) {
		printf("|");
	    }
	    printf("%02x ", http[i]);
	    if(i % 16 == 15) {
		printf("|     %c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c\n", isprint(http[i-15])? http[i-15] : '.', 
						   		   isprint(http[i-14])? http[i-14] : '.', 
						   		   isprint(http[i-13])? http[i-13] : '.',
						   		   isprint(http[i-12])? http[i-12] : '.',
						   		   isprint(http[i-11])? http[i-11] : '.', 
						   		   isprint(http[i-10])? http[i-10] : '.', 
						   		   isprint(http[i-9])? http[i-9] : '.',
						   		   isprint(http[i-8])? http[i-8] : '.',
						   		   isprint(http[i-7])? http[i-7] : '.', 
						   		   isprint(http[i-6])? http[i-6] : '.', 
						   		   isprint(http[i-5])? http[i-5] : '.',
						   		   isprint(http[i-4])? http[i-4] : '.',
						   		   isprint(http[i-3])? http[i-3] : '.', 
						   		   isprint(http[i-2])? http[i-2] : '.', 
						   		   isprint(http[i-1])? http[i-1] : '.',
						   		   isprint(http[i-0])? http[i-0] : '.');


	    }
	}
	printf("\n\n\n");
    }
    pcap_close(handle);
    return 0;
}
