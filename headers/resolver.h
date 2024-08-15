#ifndef RESOLVER_H
#define RESOLVER_H

/**
 * @file resolver.h
 * @author your name (you@domain.com)
 * @brief 
 * @version 0.1
 * @date 2022-04-05
 * 
 * @copyright Copyright (c) 2022
 * 
 */

#include "../headers/main.h"
#include "../headers/protocol.h"

typedef struct record_t {
    uint8_t *domain;
    uint8_t *ip;
    uint8_t *class;
    uint8_t *type;
    struct in_addr ipAddress;
} record_t;


/** EXTERNAL FUNCTION PROTOTYPES **/
void check_localConf_readability(char *);

#endif