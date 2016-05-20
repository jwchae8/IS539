#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>


#define MASTER_PORT 2000

void child_bot(int id) {
    int super_fd;
    struct sockaddr_in super;
    char msg[256];
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
    while(1);
}

void super_bot(int id) {
    int i, alive;
    int master_fd, listen_fd, child_fd[8], connect_len;
    char msg[256];
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
            break;
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
        if(!strncmp(msg, "show", 4)) {
            for(i=0; i<8; i++) {
                write(child_fd[i], "show", 255);
                read(child_fd[i], msg, 255);
            }
        }
        else if(!strncmp(msg, "search", 6)) {
        }
        else if(!strncmp(msg, "read", 4)) {
        }
        else if(!strncmp(msg, "create", 6)) {
        }
        else if(!strncmp(msg, "send", 4)) {
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
    char cmd[100], msg[256];
    char *param, *filename, *ipport;
    int nparam;
    int listen_fd, connect_fd[4], connect_len;
    struct sockaddr_in master, super;    
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
                msg = "search ";
                strcat(msg, param);
                write(connect_fd[nparam/8], msg, 255);
                read(connect_fd[nparam/8], msg, 255);
                printf("[%d:%d] alive\n", 1001+nparam/8, nparam);
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
                    msg = "date ";
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
                    msg = "date ";
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
            filename = strtok(NULL, " ");
            err = 1;
            while((param = strtok(NULL, " ")) != NULL) {
                err = 0;
                nparam = atoi(param);
                if(nparam < 1 || nparam > 32) {
                    err = 1;
                    break;
                }
                msg = "create ";
                strcat(msg, param);
                strcat(msg, " ");
                strcat(msg, filename);
                write(connect_fd[nparam/8], msg, 255);
                read(connect_fd[nparam/8], msg, 255);
                printf("[%d] %s_%d is created\n", nparam, filename, nparam);
            }
            if(err) {
                printf("No argument given OR Wrong argument given\n");
            }
        }
        else if(!strncmp(param, "send", 4)) {
            ipport = strtok(NULL, " ");
            err = 1;
            while((param = strtok(NULL, " ")) != NULL) {
                err = 0;
                nparam = atoi(param);
                if(nparam < 1 || nparam > 32) {
                    err = 1;
                    break;
                }
                msg = "send ";
                strcat(msg, param);
                strcat(msg, " ");
                strcat(msg, ipport);
                write(connect_fd[nparam/8], msg, 255);
                read(connect_fd[nparam/8], msg, 255);
                printf("[%d] %s_%d is created\n", nparam, filename, nparam);
            }
            if(err) {
                printf("No argument given OR Wrong argument given\n");
            }
        }
        else {
            printf("Undefined command\n");
            usage();
        }
    }
    return 0;
}
