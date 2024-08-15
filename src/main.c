#include <stdio.h>
#include "../headers/network.h"
#include "../headers/main.h"
#include "../headers/resolver.h"

server_t server;

/**
 * @brief 
 * 
 */
int main(int argc, char **argv) {

    server.localConf = "localHost.conf";   
    check_localConf_readability(server.localConf);
    startListener(&server, 53);
    return 0;
}