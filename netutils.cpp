#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <iostream>
#include <netdb.h>
#include <cstring>
#include <cerrno>
#include <unistd.h> 
#include "netutils.hpp"
#include <byteswap.h>

uint16_t calculate_icmp_checksum(uint8_t *buf, size_t bytecount) {
    uint32_t acc = 0;

    // This technically will fail for odd bytecounts.
    for(int i = 0; i <= bytecount/2; i++) {
        acc += __bswap_16(((uint16_t *)buf)[i]);
    }

    acc = (acc & 0x0000ffff) + ((acc & 0xffff0000) >> 16);

    return __bswap_16((~acc) & 0xffff);
}

uint8_t *TracertRenderer(TracertPacket *src, int payloadsize) {
    uint8_t *packet = (uint8_t *)malloc(sizeof(uint8_t) * payloadsize);
    memset(packet, 0, sizeof(uint8_t) * payloadsize);

    /******** HEADER IP ********/
    /******** offset 0 ********/
    packet[0] |= src->Version << 4;
    packet[0] |= src->IHL;
    packet[1] |= src->DCSP << 2;
    packet[1] |= src->ECN;
    *(int16_t *)(&packet[2]) |= __bswap_16(src->TotalLength); 

    /******** offset 32 ********/
    *(int16_t *)(&packet[4]) |= __bswap_16(src->Identification);    
    *(int16_t *)(&packet[7]) |= src->Flags << 13;
    *(int16_t *)(&packet[7]) |= src->FragmentOffset;
    
    /******** offset 64 ********/
    packet[8] = src->TTL;
    packet[9] = src->Protocol;

    /******** offset 96 ********/
    *(int32_t *)(&packet[12]) = __bswap_32(src->SourceIP);
    
    /******** offset 128 ********/
    packet[16] = 91;
    packet[17] = 198;
    packet[18] = 174;
    packet[19] = 194;


    /******** HEADER ICMP ********/
    // fill out ICMP header with data that we actually need, zero out the checksum
    // field.
    packet[20] = src->Type;
    packet[21] = src->Code;
    packet[22] = 0;
    packet[23] = 0;
    *(int16_t *)(&packet[24]) = __bswap_16(src->ICMPIdentifier);
    *(int16_t *)(&packet[26]) = __bswap_16(src->ICMPSequenceNumber);
    
    // use the same garbage data as unix traceroute uses.
    for(int i = 0; i < 32; i++)
        packet[28+i] = 'H'+i;

    // get icmp checksum and fill out the needed fields.
    uint16_t checksum = calculate_icmp_checksum(packet + 20, 32+6);
    *(int16_t *)(&packet[22]) = checksum;

    return packet;
}

void DebugTracertRenderer(uint8_t *buf, int packetsize) {
    printf("hexdump of traceroute packet\n");
    printf("0  1  2  3  4  5  6  7  8  9  10 11 12 13 14 15 \n");

    int emit = 0;
    for(int i = 0; i < packetsize; i++) {
        printf("%02X ", (uint8_t)buf[i]);
        if (emit == 15) {
            emit = 0;
            printf("\n");
        } else emit += 1;
    }

    printf("---- derived IPv4 packet info ----\n");
    printf("version/header length byte: %02X\n", buf[0]);
    printf("--- version = %d\n", (buf[0] & 0xF0) >> 4);
    printf("--- header length = %d\n", buf[0] & 0x0F);
    printf("Differentiated services byte: %02X\n", buf[1]);
    printf("--- DSC = %d\n", (buf[1] & 0b11111100) >> 2);
    printf("--- ECN = %d\n", buf[1] &  0b00000011);
    printf("Total length bytes: %02X %02X\n", buf[2], buf[3]);
    printf("--- total length = %d (bytes)\n", buf[2]*256 + buf[3]);
    printf("Identification bytes: %02X %02X\n", buf[4], buf[5]);
    printf("--- identification = %d\n", buf[4]*256 + buf[5]);
    printf("FLAGS bytes: %02X %02X\n", buf[6], buf[7]);
    printf("TTL byte %02X TTL = %d\n", buf[8], buf[8]);
    printf("PROTO byte %02X, protocol %d\n", buf[9], buf[9]);
    printf("Header checksum: %02X %02X\n", buf[10], buf[11]);
    printf("Source = %02X %02X %02X %02X\n", buf[12], buf[13], buf[14], buf[15]);
    printf("Source = %d.%d.%d.%d\n", buf[12], buf[13], buf[14], buf[15]);
    printf("Source = %02X %02X %02X %02X\n", buf[16], buf[17], buf[18], buf[19]);
    printf("Source = %d.%d.%d.%d\n", buf[16], buf[17], buf[18], buf[19]);
    printf("---- derived ICMP packet info ----\n");
    printf("\n");
}

int GetSocket(int proto) {
    int sockfd;

    if((sockfd = socket(AF_INET, SOCK_RAW, proto)) < 0) {
        printf("[critical] could not reserve socket. Terminating\n");
        printf("are you running with superuser privileges?\n");
        exit(1);
    }

    return sockfd;
}

uint64_t char2uint(char *ip) {
    return ((int64_t)ip[2] & 0xff) << 24 | ((int64_t)ip[3] & 0xff) << 16 | ((int64_t)ip[4] & 0xff) << 8 | ((int64_t)ip[5] & 0xff);
}

void RenderHexIp(uint64_t ip) {
    int a, b, c, d;
    a = ip & 0xff;
    b = (ip >> 8) & 0xff;
    c = (ip >> 16) & 0xff;
    d = (ip >> 24) & 0xff;
    printf("%d.%d.%d.%d\n", d, c, b, a);
}

sockaddr_in GetRecipient(char *hosthint) {
    struct addrinfo hints;
    struct addrinfo *result;
    memset(&hints, 0, sizeof(hints));
    
    struct addrinfo *addrptr = result;
    hints.ai_family = AF_INET;    /* Allow IPv4 or IPv6 */
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_flags = AI_PASSIVE;    /* For wildcard IP address */
    hints.ai_protocol = 0;          /* Any protocol */
    hints.ai_canonname = NULL;
    hints.ai_addr = NULL;
    hints.ai_next = NULL;


    int s = getaddrinfo(const_cast<char*>(hosthint), NULL, &hints, &result);
    printf("getaddrinfo status %s %d\n", std::strerror(errno), errno);

    if (s != 0) {
        sockaddr_in t;
        memset(&t, 0, sizeof(t));
        return t;
    } else {
        for(addrptr = result; addrptr != NULL; addrptr = addrptr->ai_next) {
            //std::cout << addrptr->ai_family << " " << addrptr->ai_protocol << " " << addrptr->ai_addrlen << std::endl;
            if (addrptr->ai_family == 2) {
                //printf("%X\n", addrptr->ai_addr->sa_data);
                //printf("%X\n", char2uint(addrptr->ai_addr->sa_data));
                //RenderHexIp(char2uint(addrptr->ai_addr->sa_data));
                sockaddr_in tmp;
                tmp.sin_addr.s_addr = char2uint(addrptr->ai_addr->sa_data);
                return tmp;
            }
            
        }
    }
}

void EmitPacket(uint8_t *buf, uint16_t bufsize, int sockfd, sockaddr_in recipient) {
    sockaddr_in servaddr;
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = recipient.sin_addr.s_addr;
    servaddr.sin_port = htons(35000);

    int wc = 0;
    if((wc = sendto(sockfd, buf, bufsize, 0, (struct sockaddr *)&servaddr, sizeof(servaddr))) < 0) {
        printf("write failed\n");
        printf("write status %s %d\n", std::strerror(errno), errno);
        exit(1);
    }
}