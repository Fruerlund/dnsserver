#ifndef MAIN_H
#define MAIN_H


/** GLOBAL HEADERS **/
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <sys/types.h>
#include <stddef.h>

typedef struct server_t {

    int server_fd;
    int isListening;

    /** Local DOMAIN resolving **/
    char *localConf;
    int localResolveAvailable;
    FILE *localConfFile;

    /** Extern DOMAIN resolving **/
    char *externResolver;

} server_t;

#endif