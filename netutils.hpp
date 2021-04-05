#include "inttypes.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <iostream>
#include <netdb.h>
#include <cstring>

struct TracertPacket {
    // IPv4
    uint64_t Version : 4;
    uint64_t IHL : 4;
    uint64_t DCSP : 6;
    uint64_t ECN : 2;
    uint64_t TotalLength : 16;

    uint64_t Identification : 16;
    uint64_t Flags : 3;
    uint64_t FragmentOffset : 13;

    uint64_t TTL : 8;
    uint64_t Protocol : 8;
    uint64_t HeaderChecksum : 16;

    uint64_t SourceIP : 32;
    uint64_t DestIP : 32;
    // ICMP

    uint64_t Type : 8;
    uint64_t Code : 8;

    uint64_t ICMPIdentifier : 16;
    uint64_t ICMPSequenceNumber : 16;

    char *data;
    size_t datasize;
};

sockaddr_in GetRecipient(char *hosthint);
void RenderHexIp(uint64_t ip);
int GetSocket(int proto);
void EmitPacket(uint8_t *buf, uint16_t bufsize, int sockfd, sockaddr_in recipient);
uint8_t *TracertRenderer(TracertPacket *src, int payloadsize);
void DebugTracertRenderer(uint8_t *buf, int packetsize);