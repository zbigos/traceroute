#include "netutils.hpp"
#include "cstdio"
#include <unistd.h>
#include<netinet/ip.h>
#include<netinet/ip_icmp.h>
#include <random>
#include <time.h>
#include <signal.h>

#include "listener.hpp"

void print_as_bytes (unsigned char* buff, ssize_t length)
{
	for (ssize_t i = 0; i < length; i++, buff++)
		printf ("%.2x ", *buff);	
}

void listener() {
    printf("registering a listener!\n");
    int ppid = getppid();


	int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	if (sockfd < 0) {
		fprintf(stderr, "socket error: %s\n", strerror(errno)); 
		exit(1);
	}

    kill(ppid, SIGUSR1);

	for (;;) {
		struct sockaddr_in 	sender;	
		socklen_t 			sender_len = sizeof(sender);
		u_int8_t 			buffer[IP_MAXPACKET];

		ssize_t packet_len = recvfrom(sockfd, buffer, IP_MAXPACKET, 0, (struct sockaddr*)&sender, &sender_len);
		if (packet_len < 0) {
			fprintf(stderr, "recvfrom error: %s\n", strerror(errno)); 
			exit(1);
		}

		char sender_ip_str[20]; 
		inet_ntop(AF_INET, &(sender.sin_addr), sender_ip_str, sizeof(sender_ip_str));

        struct ip* 			ip_header = (struct ip*) buffer;
		ssize_t				ip_header_len = 4 * ip_header->ip_hl;


        if (ip_header_len > 0) {
            //printf("------------------------------------------------------------\n");
    		printf("Received IP packet with ICMP content from: %s, length = %d\n", sender_ip_str, ip_header_len);
            //print_as_bytes (buffer, ip_header_len);
            //printf("\n");
    		//print_as_bytes (buffer + ip_header_len, packet_len - ip_header_len);
            //printf("------------------------------------------------------------\n");
        }
	}
}

