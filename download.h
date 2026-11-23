#ifndef DOWNLOAD_H
#define DOWNLOAD_H

#define FTP_PORT 21
#define MAX_SIZE 1024

#include <stddef.h>

typedef struct {
    char user[MAX_SIZE];
    char password[MAX_SIZE];
    char host[MAX_SIZE];
    char path[MAX_SIZE];
    char filename[MAX_SIZE];
} URL;


int parseURL(const char *url, URL *info);
int getIP(const char *host, char *ip);
int connectSocket(const char *ip, int port);
int readResponse(int sockfd, char *response, size_t size);
int sendCommand(int sockfd, const char *command);
int loginFTP(int sockfd, const URL *info);
int setBinaryMode(int sockfd);
int enterPassiveMode(int sockfd, char *ip, int *port);
int downloadFile(int ctrlSock, int dataSock, const char *path, const char *filename);
int checkTransferResponse(int ctrlSock);
int quitFTP(int sockfd);


#endif