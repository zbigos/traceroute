#include "netutils.hpp"
#include "cstdio"
#include <unistd.h>
#include<netinet/ip.h>
#include<netinet/ip_icmp.h>
#include <random>
#include <time.h>
#include <signal.h>
#include <sys/select.h>
#include "listener.hpp"
#include <chrono>
#include <sys/time.h>
#include <ctime>
#define _GNU_SOURCE     /* To get defns of NI_MAXSERV and NI_MAXHOST */
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <linux/if_link.h>


using std::vector;
using std::pair;
using std::make_pair;
using std::string;

using std::chrono::milliseconds;
using std::chrono::system_clock;
using std::chrono::duration_cast;

void mk_icmpframe(TracertPacket *tpacket, int TTL, int32_t own_ip) {
    tpacket->Version = 4;
    tpacket->IHL = 5;
    tpacket->DCSP = 0;
    tpacket->ECN = 0;
    tpacket->TotalLength = 60;

    tpacket->Identification = rand()%8000;
    tpacket->Flags = 0;
    tpacket->FragmentOffset = 0;

    tpacket->TTL = TTL;
    tpacket->Protocol=1;

    tpacket->SourceIP=own_ip;
    tpacket->DestIP=0xdead; 

    tpacket->Type = 8; //echo (request)
    tpacket->Code = 0;

    tpacket->ICMPIdentifier = 0x0dc5;
    tpacket->ICMPSequenceNumber = 0x0022;
}

int64_t get_ms() {
    return std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
}

void worker(int32_t own_address) {
    sockaddr_in addr = GetRecipient("www.wikipedia.com");
    printf("tracing ");
    RenderHexIp(addr.sin_addr.s_addr);
    printf("from ");
    RenderHexIp(own_address);
    
    int OutSockFd = GetSocket(IPPROTO_RAW);
    int InSockFd = GetSocket(IPPROTO_ICMP);

    for(int i = 1; i < 15; i++) {
        TracertPacket *tpacket = (TracertPacket *)malloc(sizeof(TracertPacket));
        mk_icmpframe(tpacket, i, own_address);

        uint8_t *buf = TracertRenderer(tpacket, 80);
        //DebugTracertRenderer(buf, 80);

        int64_t now = get_ms();
        for(int msgIt = 0; msgIt < 3; msgIt += 1)
            EmitPacket(buf, 60, OutSockFd, addr);

        struct timeval tv;
        fd_set readfds;
        tv.tv_sec = 1;
        tv.tv_usec = 0;

        FD_ZERO(&readfds);
        FD_SET(InSockFd, &readfds);

		u_int8_t 			buffer[IP_MAXPACKET];
		struct sockaddr_in 	sender;	
        socklen_t 			sender_len = sizeof(sender);

        vector <pair <string, int64_t> > ICMPresponses;

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
    			    fprintf(stderr, "failed to read the recvsocket: %s\n", strerror(errno)); 
	        	}

                string sender_ip_str(20, ' ');

                inet_ntop(AF_INET, &(sender.sin_addr), &sender_ip_str[0], sizeof(sender_ip_str));
                //printf ("Received IP packet with ICMP content from: %s\n", sender_ip_str);
                ICMPresponses.push_back(
                    make_pair(
                        sender_ip_str, 
                        get_ms() - now
                    )
                );

                if (ICMPresponses.size() == 3)
                    break;
            } else {
                if (ICMPresponses.size() < 3) {
                    ICMPresponses.push_back(make_pair("***", 0));
                } else break;
            }
        }

        for(int i = 0; i < ICMPresponses.size(); i++) {
            std::cout << "(" <<  ICMPresponses[i].second << ")" << ICMPresponses[i].first << " ";
        }

        printf("\n");
    }
}


/*
 * mniej więcej ukradnięte z manpages.
 * https://man7.org/linux/man-pages/man3/getifaddrs.3.html
 * to prawdopodobnie nie jest najlepsze rozwiązanie. Można byłoby poprosić
 * kernel żeby wygenerował nam jakieś używalne IP - chociażby pingując 1.1.1.1
 * i czytając zwrócony pakiet ICMP. Ale to jest wystarczająco dobre, na pewno lepsze
 * niż używanie
 *  - wpisanego na chama do structa 192.168.x.x 
 *  - używania niesurowego gniazda ICMP.
 */
void get_ipvaddrs(vector<char *> *out) {
    struct ifaddrs *ifaddr;
    int family, s;

    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        exit(EXIT_FAILURE);
    }
    
    for (struct ifaddrs *ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL)
            continue;
        if (ifa->ifa_addr->sa_family == AF_INET) {
            char *host = (char *)malloc(sizeof(char) * NI_MAXHOST);
            s = getnameinfo(ifa->ifa_addr, sizeof(struct sockaddr_in), host, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
            out->push_back(host);
        }
    }

    freeifaddrs(ifaddr);
}

int main() {
    srand(time(NULL));

    vector <char *> ip_addresses;
    vector <int32_t> vaddrs;

    get_ipvaddrs(&ip_addresses);
    
    for(int i= 0; i < ip_addresses.size(); i++) {
        struct in_addr addr;        
        inet_aton(ip_addresses[i], &addr);

        u_char b1, b2, b3, b4;
        b1 = addr.s_addr & 0xff;
        b2 = (addr.s_addr >> 8) & 0xff;
        b3 = (addr.s_addr >> 16) & 0xff;
        b4 = (addr.s_addr >> 24) & 0xff;
        
        if(b1 == 192 && b2 == 168)
            vaddrs.push_back(addr.s_addr);
        
        //printf("moje - %d.%d.%d.%d\n", b1, b2, b3, b4);

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
        for(int i= 0; i < fbackip_addresses.size(); i++)
            printf("%s\n", fbackip_addresses[i]);
        exit(1);
    } else if(vaddrs.size() > 1) {
        printf("[info] there are more than one addresses that seem to be valid\n");
        printf("rolling with %s then\n", vaddrs[0]);
        faddr = vaddrs[0];
    } else {
        faddr = vaddrs[0];
    }

    worker(__bswap_32(faddr));

    return 0;
}