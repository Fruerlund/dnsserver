#ifndef PROTOCOL_H
#define PROTOCOL_H

/** LOCAL HEADERS **/
#include "../headers/main.h"
#include "../headers/network.h"
#include "../headers/resolver.h"

#define DNS_PACKET_MAX_SIZE 512


/*
If set to 1 repetive Data is referrenced by pointers.
Pointers are 2 octets wide and first two bits set to 1.

EXAMPLE:
0000   80 32 53 a0 9d 12 b8 ec a3 15 2f 39 08 00 45 00   .2S......./9..E.
0010   00 89 33 dc 00 00 7b 11 3a 65 08 08 08 08 c0 a8   ..3...{.:e......
0020   00 6b 00 35 e2 4e 00 75 82 12 

[HEADER]
                                     7a 09 81 80 00 01   .k.5.N.u..z.....
0030   00 02 00 00 00 00 

[QUERY]
                         0d 63 61 6c 6c 69 6e 67 63 64   .......callingcd
0040   6e 64 65 76 04 62 6c 6f 62 04 63 6f 72 65 07 77   ndev.blob.core.w
0050   69 6e 64 6f 77 73 03 6e 65 74 00 00 01 00 01 

[ANSWERS]
                                                    c0   indows.net......
0060   0c 00 05 00 01 00 00 00 3c 00 1c 04 62 6c 6f 62   ........<...blob
0070   0e 6d 77 68 30 32 70 72 64 73 74 72 30 32 61 05   .mwh02prdstr02a.
0080   73 74 6f 72 65 c0 1f c0 41 00 01 00 01 00 00 00   store...A.......
0090   3c 00 04 34 ef c1 44                              <..4..D


0xc00c is the POINTER.

          [2 byte]     [6 byte]
0xc00c -> 1100 0000     0000 1100

Offset is then 00 0000 0000 1100 equal to 0x0c (12 bytes) from the first octet of the ID field which leads to the label in the query.

0x28 + 0x0c -> 0x52
*/

#define DNS_USE_COMPRESSION 1

#define DNS_DEFAULT_TTL 600

/* QR
 * a one bit field that specifies whether this message is a query
 * or a response
 */
#define QR_QUERY        0
#define QR_RESPONSE     1

/* OPCODE
 * a four bit field that specifies kind of query in this message
 */
#define OPCODE_QUERY    0 /* a standard query */
#define OPCODE_IQUERY   1 /* an inverse query */
#define OPCODE_STATUS   2 /* a server status request */
/* 3-15 reserved for future use */

/* AA
 * one bit, valid in responses, and specifies that the responding
 * name server is an authority for the domain name in question
 * section
 */
#define AA_NONAUTHORITY     0
#define AA_AUTHORITY        1


/* Types
*/
#define A_RECORD        0x0001
#define NS_RECORD       0x0005
#define CNAME_RECORD    0x0002
#define MX_RECORD       0x000f

/* Classes
*/
#define IP_CLASS        0x0001


/**
 * @brief 
    [0]             QR      Specify if message is query(0) or response(1)
    [1, 2, 3, 4]    Opcode  Type of query use (0 for standard query) 
    [5]             AA      Authoritative Answer specification
    [6]             TC      Specifies if message was truncated 
    [7]             RD      Recursion Desired. Set if NS should pursue the query
    [8]             RA      Recursion Available. Set if NS supports recursion. Cleraed in response 
    [9, 10, 11]     Z       Reserved for future use. Must be set to (0)
    [12, 13, 14, 15]RCODE   0: No error condition, 1: Format error, 2: Server failure. 3: Name error. 4: Not Implemented 5: Refused
 * @return typedef struct 
 */

typedef struct __attribute__((__packed__)) DNS_FLAGS {
    uint8_t QR;
    uint8_t OPCODE;
    uint8_t AA;
    uint8_t TC;
    uint8_t RD;
    uint8_t RA;
    uint8_t Z;
    uint8_t RCODE;
} DNS_FLAGS;


/**
 * @brief https://mislove.org/teaching/cs4700/spring11/handouts/project1-primer.pdf
 * @return typedef struct 
 */
typedef struct __attribute__((__packed__)) DNS_HEADER {

    uint16_t id;            // Copied to corresponding reply to match quries to replies. Randomly generated for each request
    DNS_FLAGS flags;
    uint16_t QDCOUNT;     // Number of entries in the question section.
    uint16_t ANCOUNT;     // Number of resource records in the answer section.
    uint16_t NSCOUNT;     // Number of name server resource records.
    uint16_t ARCOUNT;     // Number of resource records in teh additional sections.

} DNS_HEADER;


/**
 * @brief 
 * 
 * @return typedef struct 
 */
typedef struct __attribute__((__packed__)) DNS_QUESTION {


    char QNAME[256];        // Domain name represented as sequence of labels. Each lebel consists of a length octet followed by that number of octets. Termiantes with zero length octet.
    uint16_t QTYPE;         // Specifies the type of query.     See type
    uint16_t QCLASS;        // Specifies the class of query.    Se classes.
    
} DNS_QUESTION;


/**
 * @brief 
 * 
 * @return typedef struct 
 */
typedef struct __attribute__((__packed__)) DNS_ANSWER {

    uint16_t NAME;          // Queried domain name in LABEL format.
    uint16_t TYPE;          // Species the meaning of data in RDATA field. See types.
    uint16_t CLASS;         // RDATA field class.
    uint16_t RDLENGTH;      // Length of RDATA field.
    uint32_t TTL;           // Number of seconds results can be cached.
    char RDATA[256];        // Data of response.

} DNS_ANSWER;


/**
 * @brief 
 * 
 * @return typedef struct 
 */
typedef struct __attribute__((__packed__)) DNS_PACKET {
    
    DNS_HEADER HEADER;
    DNS_QUESTION **questions; // Pointer to array of DNS questions
    DNS_ANSWER **answers;
    
    char *data;
    uint32_t bufferOffset;

} DNS_PACKET;

/** EXTERNAL FUNCTION DEFINITIONS **/
void displayDNSHeader(DNS_HEADER *);
void displayDNSQuestion(DNS_QUESTION *);
void recieveDNSRequest(uint8_t, char *);

#endif