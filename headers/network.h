#ifndef NETWORK_H
#define NETWORK_H
/**
 * @file network.h
 * @author your name (you@domain.com)
 * @brief 
 * @version 0.1
 * @date 2022-04-04
 * 
 * @copyright Copyright (c) 2022
 * 
 */


/** LOCAL HEADERS **/
#include "../headers/main.h"

/** GLOBAL HEADERS **/
#include <netinet/in.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>  
#include <fcntl.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <linux/if_packet.h>
#include <net/ethernet.h> /* the L2 protocols */

#define MAX_CONNECTIONS 10

/** EXTERNAL FUNCTION DEFINITIONS **/
int startListener(server_t *, int);


#endif