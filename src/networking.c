/**
 * @file networking.c
 * @author your name (you@domain.com)
 * @brief 
 * @version 0.1
 * @date 2022-04-04
 * 
 * @copyright Copyright (c) 2022
 * 
 */

#include "../headers/network.h"
#include "../headers/main.h"
#include "../headers/protocol.h"

/** INTERNAL FUNCTION PROTOTYPES **/
int createUDPsocket(void);
void serverHandler(int);
void serverLoop(int, struct sockaddr *);


/**
 * @brief Creates a UDP datagram socket. 
 * 
 * @return socket descriptor of type int 
 */
int createUDPsocket(void) {

    int fd = -1;

    fd = socket(AF_INET, SOCK_DGRAM, 0);

    if(fd == 0) {
        return -1;
    }
    
    return fd;
    
}


/**
 * @brief Starts a listener on specified PORT. Uses a UDP D_GRAM socket.
 * 
 * @param port 
 * @return int 
 */
int startListener(server_t *server, int port) {

    int socket = createUDPsocket();
    server->server_fd = socket;

    if(socket == -1) {
        printf("[-]: createUDPsocket() returned -1\n");
    }

    struct sockaddr_in address;
    int opt = 1;

    if( (setsockopt(server->server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &port, sizeof(opt))) ) {
        printf("[-]: setsockopt() failed\n");
        return -1;
    }


    address.sin_port = htons(port);
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;

    int addrLen = sizeof(address);

    /* BIND AND LISTEN */
    if( bind(socket, (struct sockaddr *)&address, sizeof(address)) < 0) {
        printf("[-]: bind() failed!\n");
    }


    server->isListening = 1;
    serverLoop(socket, (struct sockaddr *)&address);
}


/**
 * @brief 
 * 
 * @param client 
 */
void serverHandler(int client) {
    char buffer[DNS_PACKET_MAX_SIZE];
    char reply[DNS_PACKET_MAX_SIZE];
    bzero(buffer, DNS_PACKET_MAX_SIZE);
    recieveDNSRequest(client, buffer);
}


/**
 * @brief Continualy recieves and passes requests to the serverHandler
 * 
 * @param socket 
 * @param address 
 * @param length 
 */
void serverLoop(int socket, struct sockaddr *address) {
    printf("[+]: DNS SERVER STARTED - LISTENING!\n");
    while(1) {
        serverHandler(socket); 
    }
}