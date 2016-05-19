#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>


#define MASTER_PORT 2000

void child_bot(int id) {
}

void super_bot(int id) {
    int i;
    int master_fd;
    char msg[256];
    struct sockaddr_in master;
    master_fd = socket(AF_INET, SOCK_STREAM, 0);
    bzero((char *)&master, sizeof(master));
    master.sin_family = AF_INET;
    master.sin_addr.s_addr = inet_addr("127.0.0.1");
    master.sin_port = htons(MASTER_PORT);
    if(connect(master_fd, (struct sockaddr*) &master, sizeof(master)) < 0) {
    }
    sprintf(msg, "%d %d", id, 8);
    write(master_fd, msg, 255);
    while(1);
    /*for(i=1; i<=32; i++) {
        if(fork()) {
            child_bot(i);
            break;
        }
    }*/
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
    int i;
    char cmd[20], msg[256];
    int listen_fd, connect_fd[4], connect_len;
    struct sockaddr_in master, super;    
    int super_id, child_num;

    printf("booting botnet...\n");
    listen_fd = socket(AF_INET, SOCK_STREAM, 0);
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
            break;
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
            printf("Child bot spawning failed\n");
            return -1;
        }
        printf("report %d:[%d, %d, %d, %d, %d, %d, %d, %d]\n", super_id, (super_id-1001) * 8 + 1, (super_id-1001) * 8 + 2, (super_id-1001) * 8 + 3, (super_id-1001) * 8 + 4, (super_id-1001) * 8 + 5, (super_id-1001) * 8 + 6, (super_id-1001) * 8 + 7, (super_id-1001) * 8 + 8);
    }

    printf("a botnet is successfully constructed!\n");
    while(1) {
        printf("botnet > ");
        scanf("%s", cmd);
        if(!strcmp(cmd, "show")) {
        }
        else if(!strcmp(cmd, "search")) {
        }
        else if(!strcmp(cmd, "read")) {
            scanf("%s", cmd);
            if(!strcmp(cmd, "-date")) {
            }
            else if(!strcmp(cmd, "-host")) {
            }
            else {
                printf("Wrong argument given\n");
                usage();
                continue;
            }
        }
        else if(!strcmp(cmd, "create")) {
        }
        else if(!strcmp(cmd, "send")) {
        }
        else {
            printf("Undefined command\n");
            usage();
        }
    }
    return 0;
}
