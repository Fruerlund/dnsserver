/**
 * @file resolver.c
 * @author your name (you@domain.com)
 * @brief 
 * @version 0.1
 * @date 2022-04-04
 * 
 * @copyright Copyright (c) 2022
 * 
 */


#include "../headers/resolver.h"

extern server_t server;

/**
 * Local DNS records are stored in a file following a format of [DOMAIN]\t[IP]\t[TYPE]
 * CLASS\tTYPE\twww.google.com\t127.0.0.1\n  
 */


/**
 * @brief A function for checking if the local.conf is readable.
 * 
 */
void check_localConf_readability(char *fileName) {

    if(server.localConf != "") {
        server.localConfFile = fopen(server.localConf, "r");
    }
    
    if(server.localConfFile == NULL) {
        server.localResolveAvailable = 0;
        printf("[-]: Local Resolving Unavailable (CONFIG: %s)\n", server.localConf);
    }

    else {
        server.localResolveAvailable = 1;
            printf("[+]: Local Resolving Available (CONFIG: %s)\n", server.localConf);

    }

}


/**
 * @brief 
 * 
 * @param domain 
 */
char * lookup(char *domain) {

    char *line = NULL;
    size_t len;
    ssize_t read;
    char *result = NULL;

    while ((read = getline(&line, &len, server.localConfFile)) != -1) {
        result = strstr(line, domain);
        if(result != NULL) {
            printf("%s() -> [+] Local RECORD available!\n", __FUNCTION__);
            return result;
        }
    }

    printf("%s() -> [-] Local RECORD not available!\n", __FUNCTION__);
    return result;

}


/**
 * @brief 
 * 
 * @param data 
 * @param record 
 */
void createRecord(char *data, record_t *record) {

    if(data != NULL) {

        char *token = strtok(data, "\t");
        record->domain = token;
        record->ip = strtok(NULL, "\t");
        record->class = strtok(NULL, "\t");
        record->type = strtok(NULL, "\t");

    }
}


char * forward_request(char *domain) {

    return NULL;
}

void resolveDomain(DNS_QUESTION *question, record_t *record) {

    char *domain = question->QNAME;
    char *result;

    if(server.localResolveAvailable) {

        result = lookup(domain);

        if(result == NULL) {
            // [-]: DOMAIN LOCAL RECORD DOES NOT EXIST!

            result = forward_request(domain);
            if(result == NULL) {
                // [-]: DOMAIN REMOTE RECORD DOES NOT EXIST!
                // Return ERROR
            }
            else {
                // [+]: DOMAIN REMOTE RECORD EXISTS!
            }
        }
        else {
            // [+]: DOMAIN LOCAL RECORD EXISTS!
            
        }
    }

    // Local Resolving unavailable
    else {
        result = forward_request(domain);
    }

    if(result != NULL) {

        createRecord(result, record);
        

        /*
        typedef uint32_t in_addr_t;
        struct in_addr {
            in_addr_t s_addr;
        }; 
        */

        if( (inet_aton(record->ip, &record->ipAddress)) > 0) {
            printf("%s() -> [+]: IP OK!\n", __FUNCTION__);
        }
        else {
            printf("%s() -> [-]: IP NOT OK!\n", __FUNCTION__);
        }

    }

    else {
        printf("%s() -> FAILED TO IDENTIFY DOMAIN!\n");
    }
}
