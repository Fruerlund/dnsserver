/**
 * @file protocol.c
 * @author your name (you@domain.com)
 * @brief 
 * @version 0.1
 * @date 2022-04-04
 * 
 * @copyright Copyright (c) 2022
 * 
 */

#include "../headers/protocol.h"


/** INTERNAL FUNCTION PROTOTYPES **/
void readDNSHeader(DNS_HEADER *, char *);
void initializeDNSHeader(DNS_HEADER *);
void createDNSPacket(DNS_PACKET *);
void initializeDNSQuestion(DNS_QUESTION *);
void readDNSQuestion(DNS_PACKET *, DNS_QUESTION *, uint8_t);

/**
 * @brief Prints the contents of the DNS_HEADER structure.
 * 
 * @param data 
 */
void displayDNSHeader(DNS_HEADER *head) {

    printf("\n***************   DNS HEADER  ******************\n");
    printf("%-10s: %-3d\n", "ID", head->id);
    printf("%-10s: %1d\n", "QR", head->flags.QR);
    printf("%-10s: %-3d\n","OPCODE", head->flags.OPCODE);
    printf("%-10s: %1d\n", "AA", head->flags.AA);
    printf("%-10s: %1d\n", "TC", head->flags.TC);
    printf("%-10s: %1d\n", "RD",head->flags.RD);
    printf("%-10s: %1d\n", "RA", head->flags.RA);
    printf("%-10s: %-3d\n", "RCODE", head->flags.RCODE);
    printf("%-10s: %-3d\n%-10s: %-3d\n%-10s: %-3d\n%-10s: %-3d\n", "QDCOUNT", head->QDCOUNT, "ANCOUNT", head->ANCOUNT, "NSCOUNT", head->NSCOUNT, "ARCOUNT", head->ARCOUNT);
    printf("*************** DNS HEADER END *****************\n");

}


/**
 * @brief Prints the contents of the DNS_QUESTION structure.
 * 
 * @param question 
 */
void displayDNSQuestion(DNS_QUESTION *question) {

    printf("\n\t***************   DNS QUESTION  ******************\n");
    printf("\t%10s: %s\n", "QNAME", question->QNAME);
    printf("\t%10s: %04x\n", "TYPE", question->QTYPE);
    printf("\t%10s: %04x\n", "CLASS", question->QCLASS);
    printf("\t*************** DNS QUESTION END *****************\n");

}


/**
 * @brief Parses the socket buffer data and parses it into a DNS_HEADER structure.
 * 
 * @param head 
 * @param buffer 
 */
void readDNSHeader(DNS_HEADER *head, char *buffer) {

    // Read the DNS Header ID
    head->id = (buffer[0] << 8) + buffer[1];
    
    //memcpy(head->id, buffer, sizeof(head->id));

    // Set DNS flags
    uint16_t flags = (buffer[2] << 8) + buffer[3];
    head->flags.QR = flags & 0x1;
    head->flags.OPCODE = (flags >> 1) & 0b1111;
    head->flags.AA = (flags >> 5) & 0x1;
    head->flags.TC = (flags >> 6) & 0x1;
    head->flags.RD = (flags >> 7) & 0x1;
    head->flags.RA = (flags >> 8) & 0x1;
    head->flags.Z = 0;
    head->flags.RCODE = (flags >> 12) & 0b1111;

    // Set QUERIES number.
    head->QDCOUNT = (buffer[4] << 8 ) + buffer[5];
    head->ANCOUNT = (buffer[6] << 8 ) + buffer[7];
    head->NSCOUNT = (buffer[8] << 8 ) + buffer[9];
    head->ARCOUNT = (buffer[10] << 8 ) + buffer[11];

    displayDNSHeader(head);
    
}


/**
 * @brief Zeroes out the DNS_QUESTION structure.
 * 
 * @param question 
 */
void initializeDNSQuestion(DNS_QUESTION *question) {
    bzero(question->QNAME, 256);
    question->QCLASS = -1;
    question->QTYPE = -1;
}


/**
 * @brief Zeroes out the DNS_ANSWER structure.
 * 
 * @param answer 
 */
void initializeDNSAnswer(DNS_ANSWER *answer) {
    answer->NAME = 0;
    answer->TYPE = 0;
    answer->CLASS = 0;
    answer->TTL = 0;
    answer->RDLENGTH = 0;
    memset(answer->RDATA, 0x0, 256);
}


/**
 * @brief Zeroes out the DNS_HEADER structure.
 * 
 * @param head 
 */
void initializeDNSHeader(DNS_HEADER *head) {

    head->id = 0;
    head->flags.QR = 0;
    head->flags.OPCODE = 0;
    head->flags.AA = 0;
    head->flags.TC = 0;
    head->flags.RD = 0;
    head->flags.RA = 0;
    head->flags.Z = 0;
    head->flags.RCODE = 0;
    head->ANCOUNT = 0;
    head->ARCOUNT = 0;
    head->NSCOUNT = 0;
    head->QDCOUNT = 0;
}


/**
 * @brief Zeroes out the DNS_PACKET structure.
 * 
 * @param packet 
 */
void createDNSPacket(DNS_PACKET *packet) {
    packet->bufferOffset = 0;
    packet->data = 0;
    packet->questions = (DNS_QUESTION **)calloc(1, sizeof (DNS_QUESTION *));
    packet->answers = (DNS_ANSWER **)calloc(1, sizeof (DNS_ANSWER *));

}


/**
 * @brief Parses the labelled DOMAIN name request and structures it into a string used for internal / external lookup
 * 
 * @param question 
 */
void readDNSQuestion(DNS_PACKET *packet, DNS_QUESTION *question, uint8_t questionIndex) {

    uint8_t index = 0;
    
    char label = packet->data[packet->bufferOffset++];
    question->QNAME[index++] = label;

    while(1) {

        for(int i = 0; i < label; i++) {
            question->QNAME[index] = packet->data[packet->bufferOffset++];
            index++;    
        }

        label = packet->data[packet->bufferOffset++];

        if(label == '\x00') {
            question->QNAME[index++] = '\x00';
            break;
        }    

        question->QNAME[index++] = label;

    }

    /*BUG: PARSING THE TYPE AND QCLASS IS INCORRECT !!! */
    packet->bufferOffset = packet->bufferOffset + index - 1;
    question->QCLASS = IP_CLASS; //packet->data[packet->bufferOffset] << 8 + packet->data[packet->bufferOffset+1];
    packet->bufferOffset = packet->bufferOffset + 2;
    question->QTYPE = A_RECORD;//packet->data[packet->bufferOffset] << 8 + packet->data[packet->bufferOffset+1];
    packet->bufferOffset = packet->bufferOffset + 2;

    packet->answers[questionIndex]->TYPE = question->QTYPE;
    packet->answers[questionIndex]->CLASS = question->QCLASS;
    packet->answers[questionIndex]->TTL = DNS_DEFAULT_TTL;

    displayDNSQuestion(question);

}

/**
 * @brief 
 * 
 * @param buffer 
 * @param bufferSize 
 * @return uint8_t 
 */
int getBufferSize(char *buffer, uint16_t size) {


    int x = size - 1;
    char c;

    if( !buffer ) {
        return 0;
    }

    while( (c =  buffer[x]) == 0x0) {
        x--;
    }
    if(x < 0) {
        printf("%s() --> [-]: ERROR!\n", __FUNCTION__);
        return -1;
    }
    
    return x+1;
}


uint16_t flagToINT(DNS_FLAGS *flags) {

    uint16_t temp = 0;


   temp = temp + flags->QR;
   temp = temp + ( (flags->OPCODE) << 1);
   /*temp = temp + ( (flags->AA) << 5);
   temp = temp + ( (flags->TC) << 6);
   temp = temp + ( (flags->RD) << 7);
   temp = temp + ( (flags->RA) << 8);
   temp = temp + ( (flags->Z) << 9);
   temp = temp + ( (flags->RCODE) << 12);*/

    return temp;
}

/**
 * @brief 
 * 
 * @param packet 
 * @param buffer 
 */
void copyToBuffer(DNS_PACKET *p, char *buffer) {

    /* */
    uint bufferOffset = 0;
    char tmp = 0;

    p->HEADER.id = htons(p->HEADER.id);
    memcpy(buffer, &p->HEADER.id, sizeof(p->HEADER.id));

    bufferOffset = 2;

    // Manually copy the DNS FLAGs into the buffer
    uint16_t flags = htons(0x8180);//flagToINT(&p->HEADER.flags);
    memcpy(buffer+bufferOffset, &flags, sizeof(flags));
    bufferOffset = 4;

    // Copy the rest of the DNS_HEADER from the DNS_PACKET

    int an, qd, ns, ar = 0;
    an = p->HEADER.ANCOUNT;
    qd = p->HEADER.QDCOUNT;
    ns = p->HEADER.NSCOUNT;
    ar = p->HEADER.ARCOUNT;

    p->HEADER.ANCOUNT = htons(p->HEADER.ANCOUNT);
    p->HEADER.QDCOUNT = htons(p->HEADER.QDCOUNT);
    p->HEADER.NSCOUNT = htons(p->HEADER.NSCOUNT);
    p->HEADER.ARCOUNT = htons(p->HEADER.ARCOUNT);

    memcpy(buffer+bufferOffset, &p->HEADER.QDCOUNT, sizeof(uint16_t) * 4);
    bufferOffset = 12;

    for(int i = 0; i < qd; i++) { 

        /* Copy QNAME*/
        int size = getBufferSize(p->questions[i]->QNAME, 256);
        memcpy(buffer + bufferOffset, &p->questions[i]->QNAME, size);
        bufferOffset += size + 2;

        // CONTINUE HERE. BUFFER IS INCORRECTLY PARSED

        /* COpies QCLASS/QTYPE */
        memcpy(buffer + bufferOffset, &p->questions[i]->QTYPE, sizeof(uint16_t) * 2);
        bufferOffset += sizeof(uint16_t) * 2;

    }

    for(int i = 0; i < an; i++) {

        memcpy(buffer + bufferOffset, &p->answers[i]->NAME, sizeof(uint16_t) * 4);
        bufferOffset += sizeof(uint16_t) * 4;

        memcpy(buffer + bufferOffset, &p->answers[i]->TTL, sizeof(uint32_t));
        bufferOffset += sizeof(uint32_t);

        memcpy(buffer + bufferOffset, &p->answers[i]->RDATA, p->answers[i]->RDLENGTH);
        bufferOffset += p->answers[i]->RDLENGTH;
    }
}


/**
 * @brief 
 * 
 * @param dns_packet 
 */
uint16_t sendDNSReply(DNS_PACKET *dns_packet, uint8_t server, struct sockaddr_in *client) {
    uint16_t bufferSize = 0;
    uint16_t bytesSent = 0;
    uint8_t buffer[DNS_PACKET_MAX_SIZE];
    memset(buffer, '\x00', DNS_PACKET_MAX_SIZE);
    int len = sizeof(*client);

    copyToBuffer(dns_packet, buffer);
    bufferSize = getBufferSize(buffer, DNS_PACKET_MAX_SIZE);
    bytesSent = sendto(server, buffer, bufferSize, MSG_CONFIRM, (const struct sockaddr *)client, len);
    return bytesSent;
}


/**
 * @brief 
 * 
 * @param answer 
 * @param question 
 * @param record 
 */
void generateDNSReply(DNS_ANSWER *answer, DNS_QUESTION *question, record_t *record) {

    if(record->class != IP_CLASS) {
        if(record->type != A_RECORD) {
            answer->NAME = htons(0xc00c);
            answer->CLASS = IP_CLASS;
            answer->TYPE = A_RECORD;
            memcpy(answer->RDATA, (struct in_addr *)&record->ipAddress.s_addr, sizeof(struct in_addr));
            answer->RDLENGTH = sizeof(struct in_addr);
        }
    }

}


/**
 * @brief Recieve DNS Request with X quries. Attempt to solve each query and create a response reply. 
 * 
 * @param server 
 * @param buffer 
 */
void recieveDNSRequest(uint8_t server, char *buffer) {

    DNS_PACKET dns_packet;
    struct sockaddr_in client;
    int client_address_size = sizeof(client);

    createDNSPacket(&dns_packet);
    initializeDNSHeader(&dns_packet.HEADER);

    /** Read the DNS request and format it into a DNS header**/
    int recieved_bytes = recvfrom(server, buffer, DNS_PACKET_MAX_SIZE, MSG_WAITALL, (struct sockaddr *) &client,
            &client_address_size);

    readDNSHeader(&dns_packet.HEADER, buffer);

    /** Setup HEADER for RESPONSE **/
    dns_packet.data = buffer;
    dns_packet.bufferOffset = 12;
    dns_packet.HEADER.ANCOUNT = dns_packet.HEADER.QDCOUNT;


    /* */
    switch(dns_packet.HEADER.flags.QR) {

        case QR_QUERY:

            switch(dns_packet.HEADER.flags.OPCODE) {

                case OPCODE_QUERY:

                    /* For each question allocate a structure of type DNS_QUESTION and the following ANSWER */
                    dns_packet.questions = realloc(dns_packet.questions, sizeof(DNS_QUESTION *) * dns_packet.HEADER.QDCOUNT+1);
                    dns_packet.answers = realloc(dns_packet.answers, sizeof(DNS_ANSWER *) * dns_packet.HEADER.ANCOUNT+1);

                    for(int i = 0; i < dns_packet.HEADER.QDCOUNT; i++) {

                        dns_packet.questions[i] = (DNS_QUESTION *) calloc(1, sizeof(DNS_QUESTION));
                        dns_packet.answers[i] = (DNS_ANSWER *) calloc(1, sizeof(DNS_ANSWER));
                        record_t record;

                        initializeDNSQuestion(dns_packet.questions[i]);
                        initializeDNSAnswer(dns_packet.answers[i]);

                        /* For each allocated structure parse the data and read the query */
                        readDNSQuestion(&dns_packet, (DNS_QUESTION *) dns_packet.questions[i], i);
                        
                        /* attempt to resolve the domain and update DNS_ANSWER structure */
                        resolveDomain(dns_packet.questions[i], &record);

                        /* Setup HEADER for response*/
                        dns_packet.HEADER.flags.QR = QR_RESPONSE;
                        dns_packet.HEADER.flags.RA = 0;
                        dns_packet.HEADER.flags.OPCODE = 0;
                        /* Generate reply */
                        generateDNSReply(dns_packet.answers[i], dns_packet.questions[i], &record);

                    }
                    break;

                case OPCODE_STATUS:
                    printf("[-]: Not implemented!\n");
                    break;
                default:
                    printf("[-]: Default reached!");
            }
            break;
        default:
            printf("[-]: Invalid Message type (query/response)\n");
    }

    /* Send reply */
    int result = sendDNSReply(&dns_packet, server, &client);
    if ( result < 0) {
        printf("%s() -> [-]: Failed to send DNS reply!\n", __FUNCTION__);
    }
    else {
        printf("%s() -> [+]: %d bytes sent!\n", __FUNCTION__, result);
    }
}