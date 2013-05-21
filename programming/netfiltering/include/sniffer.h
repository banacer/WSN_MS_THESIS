/*
 * sniffer.h
 *
 *  Created on: May 1, 2013
 *      Author: banacer
 */

#ifndef SNIFFER_H_
#define SNIFFER_H_
#include<netinet/in.h>
#include<errno.h>
#include<netdb.h>
#include<stdio.h> //For standard things
#include<stdlib.h>    //malloc
#include<string.h>    //strlen
#include<linux/if.h>
#include<netinet/ip_icmp.h>   //Provides declarations for icmp header
#include<netinet/udp.h>   //Provides declarations for udp header
#include<netinet/tcp.h>   //Provides declarations for tcp header
#include<netinet/ip.h>
#include<netinet/ip6.h>//Provides declarations for ip header
#include<netinet/if_ether.h>  //For ETH_P_ALL
#include<linux/if_packet.h>
#include<net/ethernet.h>  //For ether_header
#include<sys/socket.h>
#include<arpa/inet.h>
#include<sys/ioctl.h>
#include<sys/time.h>
#include<sys/types.h>
#include<unistd.h>


// Define some constants.
#define IP4_HDRLEN 20         // IPv4 header length
#define IP6_HDRLEN 40         // IPv6 header length
#define TCP_HDRLEN 20         // TCP header length, excludes options data

void ProcessPacket(unsigned char* , int);
int sendIPV6Packet(char* , int ,char* );
int sendIPV4Packet(char*, int ,char* );
unsigned short int checksum (unsigned short int *, int );
char* getIPAddr(char* , int );



#endif /* SNIFFER_H_ */
