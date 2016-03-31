#include <stdio.h>
#include <stdarg.h>
#include <stdint.h>
#include <ctype.h>
#include <string.h>
#include <pcap/pcap.h>



#define PORT_MAX 65535
#define PORT_MIN 0

#define BUFLEN 2048

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
    for(i=0; i<strlen(str)-1; i++) {
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
    for(i=0; i<strlen(str)-1; i++) {
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
    for(i=0; i<strlen(str)-1; i++) {
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

struct rule {
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
    uint8_t flag;

    /* tcp payload */
    unsigned char* http_request;
    unsigned char* content;

    /* next rule */
    struct rule *next_rule;
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
    char rule_token[BUFLEN];
    char field[20], *colon, *lquote, *rquote;
    struct rule* new_rule;
    struct rule head;
    int pattern_rule_exists, pattern_completed;
    int rule_count = 0;

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
            continue;
        }
        fscanf(fp, "%s", rule_token);
        if(is_ip(rule_token, &(new_rule->srcip)) < 0) {
            fprintf(stderr, "[Error]Not valid ip number : given token = %s\n", rule_token);
            continue;
        }
        fscanf(fp, "%s", rule_token);
        if(is_port(rule_token, &(new_rule->srcport)) < 0) {
            fprintf(stderr, "[Error]Not valid port number : given token = %s\n", rule_token);
            continue;
        }
        fscanf(fp, "%s", rule_token);
        if(strcmp(rule_token, "->")) {
            fprintf(stderr, "[Error]Not correct format : this rule lacks directional mark: given token = %s\n", rule_token);
        }
        fscanf(fp, "%s", rule_token);
        if(is_ip(rule_token, &(new_rule->destip)) < 0) {
            fprintf(stderr, "[Error]Not valid ip number : given token = %s\n", rule_token);
            continue;
        }
        fscanf(fp, "%s", rule_token);
        if(is_port(rule_token, &(new_rule->destport)) < 0) {
            fprintf(stderr, "[Error]Not valid port number : given token = %s\n", rule_token);
            continue;
        }
        fscanf(fp, "%s", rule_token);
        if(!strcmp(rule_token, "alert")) {
            pattern_rule_exists = 0;
            continue;
        }
        pattern_rule_exists = 1;
        pattern_completed = 0;
        if(rule_token[0] == '(') {
            rule_token++;
        }
        else {
            fprintf(stderr, "[Error]Not valid pattern rule - it should be surrounded with ( and ) : given token = %s\n", rule_token);
            continue;
        }
        do{
            if((colon = strchr(rule_token, ':')) == NULL) {
                fprintf(stderr, "[Error]Not valid pattern rule - no colon : given token = %s\n", rule_token);
                break;
            }
            if((colon = strchr(rule_token, ';')) == NULL) {
                fprintf(stderr, "[Error]Not valid pattern rule - no semicolon : given token = %s\n", rule_token);
                break;
            }
            strncpy(field, rule_token, colon - rule_token);
            field[colon - rule_token] = 0;
            lquote = colon + 1;
            if(lquote[0] != '\"') {
                fprintf(stderr, "[Error]Not valid pattern rule - value should be surrounded with \"s : given token = %s\n", rule_token);
                break;
            }
            if((rquote = strrchr(rule_token, '\"')) == NULL) {
                fprintf(stderr, "[Error]Not valid pattern rule - value should be surrounded with \"s : given token = %s\n", rule_token);
                break;
            }
            if(lquote == rqoute) {
                fprintf(stderr, "[Error]Not valid pattern rule - value should be surrounded with \"s : given token = %s\n", rule_token);
                break;
            }
            if(lquote + 1 == rqoute) {
                fprintf(stderr, "[Error]Not valid pattern rule - empty value : given token = %s\n", rule_token);
                break;
            }
            if(!strcmp(field, "tos")) {
                if(process_8bit(colon+1, &(new_rule->tos)) < 0) {
                }
            }
            else if(!strcmp(field, "length")) {
                if(process_16bit(colon+1, &(new_rule->length)) < 0) {
                }
            }
            else if(!strcmp(field, "fragoffset")) {
                if(process_16bit(colon+1, &(new_rule->fragoffset)) < 0) {
                }
            }
            else if(!strcmp(field, "ttl")) { 
                if(process_8bit(colon+1, &(new_rule->ttl)) < 0) {
                }
            }
            else if(!strcmp(field, "seq")) {
                if(process_32bit(colon+1, &(new_rule->seq)) < 0) {
                }
            }
            else if(!strcmp(field, "ack")) {
                if(process_32bit(colon+1, &(new_rule->ack)) < 0) {
                }
            }
            else if(!strcmp(field, "flags")) {
                for(i=1; i<strlen(colon+1); i++) {
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
                    }
                }
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
                if(lquote == rqoute) {
                    fprintf(stderr, "[Error]Not valid pattern rule - value should be surrounded with \"s : given token = %s\n", rule_token);
                    break;
                }
                if(lquote + 1 == rqoute) {
                    fprintf(stderr, "[Error]Not valid pattern rule - empty value : given token = %s\n", rule_token);
                    break;
                }
                if(!strcmp(field, "http_request")) {
                    new_rule->http_request = (unsigned char*) malloc(sizeof(unsigned char) * (rquote - lquote) + 1);
                    strncpy(new_rule->http_request, lquote+1, rquote - lquote);
                    new_rule->http_request[rquote - lquote] = 0;
                }
                else {
                    new_rule->content = (unsigned char*) malloc(sizeof(unsigned char) * (rquote - lquote) + 1);
                    strncpy(new_rule->content, lquote+1, rquote - lquote);
                    new_rule->content[rquote - lquote] = 0;
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
        }
        if(colon != NULL) {
            fprintf(stderr, "[Error]Not valid pattern rule - miscellaneous : given token = %s\n", rule_token);
        }
    }
    fclose(fp);

    printf("From %s, IDS program added %d rules.\nNow it begins to investigate packets.\n", rule_file, rule_count);

/*    while(true) {
        packet = pcap_next(handle, &header);
        
    }
    pcap_close(handle);*/
    return 0;
}
