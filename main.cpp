/* Zbigniew Drozd 310555 */

#include "cstdio"
#include "netutils.hpp"
#include <algorithm>
#include <arpa/inet.h>
#include <chrono>
#include <ctime>
#include <ifaddrs.h>
#include <linux/if_link.h>
#include <netdb.h>
#include <random>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>

using std::vector;
using std::pair;
using std::make_pair;
using std::string;

using std::chrono::milliseconds;
using std::chrono::system_clock;
using std::chrono::duration_cast;

int64_t get_ms() {
    return std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
}

bool inrange(int a, int b, int r) {
    return (a >= b) && (a <= (b+r));
}

void worker(int32_t own_address, uint32_t target_address) {
    printf("tracing ");
    RenderHexIp(target_address);
    printf("\nfrom ");
    RenderHexIp(own_address);
    printf("\n============================================\n");

    int OutSockFd = GetSocket(IPPROTO_RAW);
    int InSockFd = GetSocket(IPPROTO_ICMP);

    for(int i = 1; i < 32; i++) {
        printf("%d. ", i);

        uint16_t ICMP_ID =  rand()%0xAFFF + 0x2000;
        uint16_t ICMP_SEQ = rand()%0xAFFF + 0x2000;
        int64_t now = get_ms();

        for(int msgIt = 0; msgIt < 3; msgIt += 1) {
            TracertPacket *tpacket = (TracertPacket *)malloc(sizeof(TracertPacket));
            mk_icmpframe(tpacket, i, own_address, target_address, ICMP_ID + msgIt, ICMP_SEQ + msgIt);
            uint8_t *buf = TracertRenderer(tpacket, 80);
            EmitPacket(buf, 60, OutSockFd, target_address);

            free(tpacket);
            free(buf);
        }

        struct timeval tv;
        fd_set readfds;
        tv.tv_sec = 1;
        tv.tv_usec = 0;

        FD_ZERO(&readfds);
        FD_SET(InSockFd, &readfds);

		u_int8_t buffer[IP_MAXPACKET];
		struct sockaddr_in 	sender;	
        socklen_t sender_len = sizeof(sender);
        vector <pair <uint32_t, int64_t> > ICMPresponses;

        while(true) {
            int retval = select(InSockFd + 1, &readfds, NULL, NULL, &tv);
            
            if(FD_ISSET(InSockFd, &readfds)) {

                ssize_t packet_len = recvfrom(
                    InSockFd, 
                    buffer, 
                    IP_MAXPACKET, 
                    0, 
                    (struct sockaddr*)&sender, 
                    &sender_len
                );

                if (packet_len < 0) {
    			    printf("[critical] failed to read the recvsocket: %s\n", strerror(errno)); 
                    exit(1);
                }

                struct ip* 			ip_header = (struct ip*) buffer;
                ssize_t				ip_header_len = 4 * ip_header->ip_hl;

                char *ICMPbuf = (char *)buffer + ip_header_len;
                uint16_t packet_id = ((uint8_t)ICMPbuf[32]) * 256 + (uint8_t)ICMPbuf[33];
                uint16_t packet_seq = ((uint8_t)ICMPbuf[34]) * 256 + (uint8_t)ICMPbuf[35];
                uint16_t alt_packet_id = ((uint8_t)ICMPbuf[4]) * 256 + (uint8_t)ICMPbuf[5];
                uint16_t alt_packet_seq = ((uint8_t)ICMPbuf[6]) * 256 + (uint8_t)ICMPbuf[7];

                uint32_t response_addr = __bswap_32((uint32_t)(sender.sin_addr.s_addr));
                if ((inrange(packet_id, ICMP_ID, 3) && inrange(packet_seq, ICMP_SEQ, 3)) || \
                ((target_address == response_addr) && inrange(alt_packet_id, ICMP_ID, 3) && inrange(alt_packet_seq, ICMP_SEQ, 3))) {
                    ICMPresponses.push_back(
                        make_pair(
                            response_addr, 
                            get_ms() - now
                        )
                    );
                }

                if (ICMPresponses.size() == 3) break;
            } else {
                if (ICMPresponses.size() < 3)
                    ICMPresponses.push_back(make_pair(0, -1));
                else break;
            }
        }

        int64_t timesum = 0;
        for(int i = 0 ; i < 3; i++)
            timesum += ICMPresponses[i].second;

        if(ICMPresponses[0].first == ICMPresponses[1].first &&
           ICMPresponses[1].first == ICMPresponses[2].first) {
            if(ICMPresponses[0].first == 0) {
                printf("*\n");
            } else {
                RenderHexIp(ICMPresponses[0].first);
                printf(" %ld.%ldms\n", timesum/3000, timesum%3000);
            }
           }
        else {
            uint32_t tadr[3];
            for(int i = 0; i < 3; i++)
                tadr[i] = ICMPresponses[i].first;

            std::sort(tadr, tadr+3);
            if(tadr[0] != 0) {
                RenderHexIp(tadr[0]);
                printf("    ");
            }

            if(tadr[0] != tadr[1] && tadr[1] != 0) {RenderHexIp(tadr[1]); printf("    ");}
            if(tadr[1] != tadr[2] && tadr[2] != 0) {RenderHexIp(tadr[2]); printf("    ");}
            
            if(tadr[0] != 0 && tadr[1] != 0 && tadr[2] != 0)
                printf(" %ld.%ldms\n", timesum/3000, timesum%3000);
            else
                printf("???\n");
        }
        // Reached target machine. Stop.
        if(ICMPresponses[0].first == target_address)
            break;
    }
}

int main(int argc, char *argv[]) {
    srand(time(NULL));

    vector <char *> ip_addresses;
    vector <int32_t> vaddrs;

    if (argc != 2) {
        printf("[critical] wrong parameters\n");
        printf("please use ./main 91.198.174.194\n");
        printf("or ./main www.wikipedia.net");
        exit(1);
    }

    sockaddr_in addr = GetRecipient(argv[1]);
    printf("resolved target to ");
    uint32_t target_ipv4 = addr.sin_addr.s_addr;
    RenderHexIp(target_ipv4);
    printf("\n");

    get_ipvaddrs(&ip_addresses);
    
    for(size_t i = 0; i < ip_addresses.size(); i++) {
        struct in_addr addr;        
        inet_aton(ip_addresses[i], &addr);

        u_char b1, b2;
        b1 = addr.s_addr & 0xff;
        b2 = (addr.s_addr >> 8) & 0xff;
        if(b1 == 192 && b2 == 168) 
            vaddrs.push_back(addr.s_addr);
        
        free(ip_addresses[i]);
    }

    int32_t faddr;
    if(vaddrs.size() == 0) {
        printf("[critical] could not find ip address of this machine.\n");
        printf("this might be explained by the machine\n");
        printf("- being not connected to the internet\n");
        printf("- network stack being configured in a weird way\n");
        printf("There is no ipv4 address starting with 192.168.\n");
        printf("\nIpv4 addresses on your machine are:\n");
        vector <char *> fbackip_addresses;
        get_ipvaddrs(&fbackip_addresses);
        for(size_t i = 0; i < fbackip_addresses.size(); i++)
            printf("%s\n", fbackip_addresses[i]);
        exit(1);
    } else if(vaddrs.size() > 1) {
        printf("[info] there are more than one addresses that seem to be valid\n");
        printf("rolling with %X then\n", vaddrs[0]);
        faddr = vaddrs[0];
    } else {
        faddr = vaddrs[0];
    }

    worker(__bswap_32(faddr), target_ipv4);

    return 0;
}