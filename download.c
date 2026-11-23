#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "download.h"

int parseURL(const char *url, URL *info) {

    // Check if the URL starts with ftp://
    if(strncmp(url, "ftp://", 6) != 0){
        fprintf(stderr, "Invalid FTP URL\n");
        return -1;
    }

    const char *start = url + 6;

    // Find the beginning of the file path
    const char *slash = strchr(start, '/');

    if(slash == NULL || *(slash + 1) == '\0'){
        fprintf(stderr, "Missing file path\n");
        return -1;
    }

    // Check URL length
    if(strlen(start) >= MAX_SIZE){
        fprintf(stderr, "URL too long\n");
        return -1;
    }

    // Check if authentication is provided
    const char *at = strchr(start, '@');

    if(at != NULL && at < slash){

        const char *colon = strchr(start, ':');

        if(colon == NULL || colon >= at){
            fprintf(stderr, "Invalid credentials\n");
            return -1;
        }

        // Extract username
        strncpy(info->user, start, colon - start);
        info->user[colon - start] = '\0';

        // Extract password
        strncpy(info->password, colon + 1, at - colon - 1);
        info->password[at - colon - 1] = '\0';

        start = at + 1;

    }else{
        // Default anonymous authentication
        strcpy(info->user, "anonymous");
        strcpy(info->password, "anonymous@");
    }

    // Extract hostname
    if(slash == start){
        fprintf(stderr, "Missing hostname\n");
        return -1;
    }

    strncpy(info->host, start, slash - start);
    info->host[slash - start] = '\0';

    // Extract file path
    strcpy(info->path, slash + 1);

    // Extract filename
    const char *lastSlash = strrchr(info->path, '/');

    strcpy(info->filename, lastSlash ? lastSlash + 1 : info->path);

    if(info->filename[0] == '\0'){
        fprintf(stderr, "Missing filename\n");
        return -1;
    }

    return 0;
}

int getIP(const char *host, char *ip){

    struct hostent *h;

    if((h = gethostbyname(host)) == NULL) {
        herror("gethostbyname()");
        return -1;
    }

    strcpy(ip, inet_ntoa(*((struct in_addr *) h->h_addr)));

    return 0;
}


int connectSocket(const char *ip, int port){

    int sockfd;
    struct sockaddr_in server_addr;

    // Initialize server address
    memset(&server_addr, 0, sizeof(server_addr));

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);

    // Convert IP string to binary format
    if(inet_pton(AF_INET, ip, &server_addr.sin_addr) != 1){
        fprintf(stderr, "Invalid IP address\n");
        return -1;
    }

    // Create TCP socket
    sockfd = socket(AF_INET, SOCK_STREAM, 0);

    if(sockfd < 0){
        perror("socket()");
        return -1;
    }

    // Connect to server
    if(connect(sockfd, (struct sockaddr *) &server_addr,sizeof(server_addr)) < 0) {

        perror("connect()");
        close(sockfd);
        return -1;
    }

    return sockfd;
}

int readResponse(int sockfd, char *response, size_t size){
    size_t total = 0;
    char c;
    int code = -1;
    int multiline = 0;

    if(response == NULL || size < 5) {
        return -1;
    }

    while (1) {

        size_t lineStart = total;
        // Read one complete line
        while(1){

            ssize_t bytes = read(sockfd, &c, 1);

            if(bytes < 0){
                perror("read()");
                return -1;
            }

            if(bytes == 0){
                fprintf(stderr, "FTP connection closed\n");
                return -1;
            }

            if(total >= size - 1){
                fprintf(stderr, "FTP response too long\n");
                return -1;
            }

            response[total++] = c;
            response[total] = '\0';

            if (c == '\n') {
                break;
            }
        }

        char *line = response + lineStart;

        // First line: identify the FTP reply code
        if (code == -1){

            if(line[0] < '0' || line[0] > '9' ||
                line[1] < '0' || line[1] > '9' ||
                line[2] < '0' || line[2] > '9'){

                fprintf(stderr, "Invalid FTP response\n");
                return -1;
            }

            code = (line[0] - '0') * 100 + (line[1] - '0') * 10 + (line[2] - '0');

            multiline = (line[3] == '-');

            if (!multiline){
                break;
            }
        }else{
            // Multiline response ends with the same
            // code followed by a space
            if(line[0] == response[0] &&
                line[1] == response[1] &&
                line[2] == response[2] &&
                line[3] == ' '){
                break;
            }
        }
    }

    return code;
}

int sendCommand(int sockfd, const char *command){
    size_t total = 0;
    size_t length = strlen(command);

    while(total < length){
        ssize_t bytes = write(sockfd, command + total, length - total);

        if(bytes <= 0){
            perror("write()");
            return -1;
        }
        total += bytes;
    }
    return 0;
}

int loginFTP(int sockfd, const URL *info){

    char command[2 * MAX_SIZE + 16];
    char response[4096];
    int code;

    // Send username
    snprintf(command, sizeof(command),"USER %s\r\n", info->user);

    if(sendCommand(sockfd, command) < 0) return -1;

    code = readResponse(sockfd, response, sizeof(response));

    if(code < 0) return -1;

    printf("USER response: %s", response);

    // Server may accept login immediately
    if(code == 230)
        return 0;

    // Otherwise, password must be requested
    if(code != 331){
        fprintf(stderr, "FTP username rejected\n");
        return -1;
    }

    // Send password
    snprintf(command, sizeof(command), "PASS %s\r\n", info->password);

    if (sendCommand(sockfd, command) < 0) return -1;

    code = readResponse(sockfd, response, sizeof(response));

    if(code < 0) return -1;

    printf("PASS response: %s", response);

    if(code != 230){
        fprintf(stderr, "FTP authentication failed\n");
        return -1;
    }

    return 0;
}

int setBinaryMode(int sockfd){
    char response[4096];

    if(sendCommand(sockfd, "TYPE I\r\n") < 0) return -1;

    int code = readResponse(sockfd, response, sizeof(response));

    if(code < 0)return -1;

    printf("TYPE response: %s", response);

    if(code != 200) {
        fprintf(stderr, "Failed to set binary mode\n");
        return -1;
    }

    return 0;
}

int enterPassiveMode(int sockfd, char *ip, int *port){
    char response[4096];
    int code;

    if(sendCommand(sockfd, "PASV\r\n") < 0) return -1;

    code = readResponse(sockfd, response, sizeof(response));

    if(code != 227){
        fprintf(stderr, "Failed to enter passive mode\n");
        return -1;
    }

    printf("PASV response: %s", response);

    // Find the beginning of the IP and port information
    char *start = strchr(response, '(');

    if(start == NULL){
        fprintf(stderr, "Invalid PASV response\n");
        return -1;
    }

    int h1, h2, h3, h4, p1, p2;
    int consumed = 0;

    if(sscanf(start, "(%d,%d,%d,%d,%d,%d)%n",
            &h1, &h2, &h3, &h4, &p1, &p2,
            &consumed) != 6 ||
        consumed == 0 ||
        (start[consumed] != '\0' &&
        start[consumed] != '\r' &&
        start[consumed] != '\n')){

        fprintf(stderr, "Invalid PASV address format\n");
        return -1;
    }

    int values[] = {h1, h2, h3, h4, p1, p2};

    for(int i = 0; i < 6; i++){
        if(values[i] < 0 || values[i] > 255){
            fprintf(stderr, "Invalid PASV values\n");
            return -1;
        }
    }

    snprintf(ip, INET_ADDRSTRLEN, "%d.%d.%d.%d",
             h1, h2, h3, h4);

    *port = p1 * 256 + p2;

    if(*port == 0){
        fprintf(stderr, "Invalid PASV port\n");
        return -1;
    }

    return 0;
}

int downloadFile(int ctrlSock, int dataSock, const char *path, const char *filename){
    char command[MAX_SIZE + 16];
    char response[4096];
    char buffer[4096];
    int code;

    // Request the file
    snprintf(command, sizeof(command),"RETR %s\r\n", path);

    if(sendCommand(ctrlSock, command) < 0) return -1;

    // Read the initial transfer response
    code = readResponse(ctrlSock, response, sizeof(response));

    if(code < 0) return -1;

    printf("RETR response: %s", response);

    if(code != 150 && code != 125){
        fprintf(stderr, "FTP file request rejected\n");
        return -1;
    }

    // Open local file in binary mode
    FILE *file = fopen(filename, "wb");

    if(file == NULL){
        perror("fopen()");
        return -1;
    }

    // Receive file data
    ssize_t bytes;
    int error = 0;

    while((bytes = read(dataSock, buffer, sizeof(buffer))) > 0){
        if(fwrite(buffer, 1, bytes, file) != (size_t) bytes){
            perror("fwrite()");
            error = 1;
            break;
        }
    }

    if(bytes < 0){
        perror("read()");
        error = 1;
    }

    if(fclose(file) != 0){
        perror("fclose()");
        error = 1;
    }

    if(error) return -1;

    printf("File data received: %s\n", filename);
    return 0;

}

int checkTransferResponse(int ctrlSock){
    char response[4096];

    int code = readResponse(ctrlSock, response, sizeof(response));

    if(code < 0) return -1;

    printf("Transfer response: %s", response);

    if(code != 226 && code != 250){
        fprintf(stderr, "FTP transfer failed\n");
        return -1;
    }

    return 0;
}

int quitFTP(int sockfd){

     char response[4096];

    // Send QUIT command
    if(sendCommand(sockfd, "QUIT\r\n") < 0) return -1;

    // Read server response
    int code = readResponse(sockfd, response, sizeof(response));

    if (code < 0) return -1;

    printf("QUIT response: %s", response);

    if(code != 221){
        fprintf(stderr, "FTP session termination failed\n");
        return -1;
    }

    return 0;
}


int main(int argc, char *argv[]){

    if(argc != 2){
        fprintf(stderr, "Usage: %s <ftp-url>\n", argv[0]);
        return -1;
    }

    URL info;
    char ip[INET_ADDRSTRLEN];

    if(parseURL(argv[1], &info) < 0){
        return -1;
    }

    printf("User:     %s\n", info.user);
    printf("Host:     %s\n", info.host);
    printf("Path:     %s\n", info.path);
    printf("Filename: %s\n", info.filename);

    if(getIP(info.host, ip)<0){
        return -1;
    }

    printf("IP:       %s\n", ip);

    int sockfd = connectSocket(ip, FTP_PORT);
    if (sockfd < 0){
        fprintf(stderr, "Failed to connect to FTP server\n");
        return -1;
    }
    printf("TCP connection established successfully!\n");

    // Read FTP welcome message
    char response[4096];

    int code = readResponse(sockfd, response, sizeof(response));

    if(code < 0){
        close(sockfd);
        return -1;
    }

    printf("Server response:\n%s", response);
    printf("FTP response code: %d\n", code);

    if(code != 220) {
        fprintf(stderr, "FTP server is not ready\n");
        close(sockfd);
        return -1;
    }

    if(loginFTP(sockfd, &info) < 0){
        fprintf(stderr, "FTP login failed\n");
        close(sockfd);
        return -1;
    }

    printf("FTP authentication successful!\n");


    // Set binary transfer mode
    if(setBinaryMode(sockfd) < 0){
        close(sockfd);
        return -1;
    }

    // Enter passive mode
    char dataIP[INET_ADDRSTRLEN];
    int dataPort;

    if(enterPassiveMode(sockfd, dataIP, &dataPort) < 0){
        close(sockfd);
        return -1;
    }

    printf("Data IP:   %s\n", dataIP);
    printf("Data Port: %d\n", dataPort);

    // Open data connection
    int dataSock = connectSocket(dataIP, dataPort);

    if(dataSock < 0){
        fprintf(stderr, "Failed to establish data connection\n");
        close(sockfd);
        return -1;
    }

    printf("Data connection established successfully!\n");

    // Download the file
    int result = downloadFile(sockfd, dataSock, info.path, info.filename);
    close(dataSock);

    if(result< 0){
        fprintf(stderr, "File download failed\n");
        close(sockfd);
        return -1;
    }

    // Check final FTP response
    if(checkTransferResponse(sockfd) < 0){
        close(sockfd);
        return -1;
    }

    printf("File downloaded successfully: %s\n", info.filename);

    // Terminate FTP session
    if(quitFTP(sockfd) < 0){
        close(sockfd);
        return -1;
    }

    // Close control connection
    close(sockfd);

    return 0;
}

