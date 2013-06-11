#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "my_sniffer.h"

int main()
{
	int sockfd,retval,data_size;
	char *buf;
	char *addr;
	char *src_addr;
	char *dest_addr;

	socklen_t clilen;
	struct sockaddr_in cliaddr;
	struct sockaddr_in *in;
	struct sockaddr_in6 *in6;
	struct iphdr *ip_hdr;
	struct ip6_hdr *ip6_hdr;
	struct ethhdr *header;

	sockfd = socket( PF_PACKET, SOCK_PACKET , htons(ETH_P_ALL));
	if (sockfd < 0)
	{
		perror("sock:");
		exit(1);
	}
	buf = (char *)calloc(10000,sizeof(char));

	clilen = sizeof(struct sockaddr_in);
	while(1)
	{
		header = (struct ethhdr* ) buf;

		data_size = recvfrom(sockfd,buf,10000,0,(struct sockaddr *)&cliaddr,&clilen);

		if(header->h_proto == 0) // MOST PROBABLY IPV6 WE SHOULD MAKE SURE IT IS
		{

			ip6_hdr = (struct ip6_hdr *)(buf);

			in6 = (struct sockaddr_in6 *) malloc(sizeof(struct sockaddr_in6));
			in6->sin6_addr.__in6_u = ip6_hdr->ip6_src.__in6_u;
			addr = calloc(INET6_ADDRSTRLEN,sizeof(char));
			inet_ntop(AF_INET6, &(in6->sin6_addr), addr, INET6_ADDRSTRLEN);

			if(ip6_hdr->ip6_nxt == 6) // This is a TCP header to be forwarded
			{
				buf += IP6_HDRLEN; // cursor is pointing towards the TCP datagram
				data_size -= IP6_HDRLEN; // size of TCP datagram buffer is adjusted
				//compute new addresses
				//src addr
				in6 = (struct sockaddr_in6 *) malloc(sizeof(struct sockaddr_in6));
				in6->sin6_addr.__in6_u = ip6_hdr->ip6_src.__in6_u;
				src_addr = calloc(INET6_ADDRSTRLEN,sizeof(char));
				inet_ntop(AF_INET6, &(in6->sin6_addr), src_addr, INET6_ADDRSTRLEN);
				free(in6);

				//dest addr
				in6 = (struct sockaddr_in6 *) malloc(sizeof(struct sockaddr_in6));
				in6->sin6_addr.__in6_u = ip6_hdr->ip6_dst.__in6_u;
				dest_addr = calloc(INET6_ADDRSTRLEN,sizeof(char));
				inet_ntop(AF_INET6, &(in6->sin6_addr), dest_addr, INET6_ADDRSTRLEN);
				free(in6);

				src_addr = cleanIPV6(src_addr);
				dest_addr = cleanIPV6(dest_addr);

				printf("src 6 addr %s  , 4 addr %s\n",src_addr, translate(6,src_addr));
				printf("des 6 addr %s  , 4 addr %s\n",dest_addr, translate(6,dest_addr));

				sendIPV4Packet(buf,data_size,translate(6,src_addr),translate(6,dest_addr));

				free(src_addr);
				free(dest_addr);


			}
		}
		else if(header->h_proto == 8)
		{
			ip_hdr = (struct iphdr *)(buf + sizeof(struct ethhdr));
			if(ip_hdr->protocol == 6) // check if it is TCP
			{
				buf += (sizeof(struct ethhdr)+ IP4_HDRLEN);
				data_size -= (sizeof(struct ethhdr)+ IP4_HDRLEN);
				//compute new addresses
				//src addr
				in = (struct sockaddr_in *) malloc(sizeof(struct sockaddr_in));
				in->sin_addr.s_addr = ip_hdr->saddr;
				src_addr = calloc(INET_ADDRSTRLEN,sizeof(char));
				inet_ntop(AF_INET, &(in->sin_addr), src_addr, INET_ADDRSTRLEN);
				free(in);

				//dest addr
				in = (struct sockaddr_in *) malloc(sizeof(struct sockaddr_in));
				in->sin_addr.s_addr = ip_hdr->daddr;
				dest_addr = calloc(INET_ADDRSTRLEN,sizeof(char));
				inet_ntop(AF_INET, &(in->sin_addr), dest_addr, INET_ADDRSTRLEN);
				free(in);

				//printf("src 4 addr %s len = %d , 6 addr %s\n",src_addr,strlen(src_addr), translate(4,src_addr));
				//printf("des 4 addr %s len = %d , 6 addr %s\n",dest_addr, translate(4,dest_addr));

				sendIPV6Packet(buf,data_size,translate(4,src_addr),translate(4,dest_addr));

				free(src_addr);
				free(dest_addr);

			}
		}

	}
}
int sendIPV6Packet(char* buffer,int size,char *src ,char *dest)
{
	int status, frame_length, sd, bytes;
    char *interface, *target, *src_ip, *dst_ip;
    struct ip6_hdr iphdr;



    unsigned char *src_mac, *dst_mac, *ether_frame;
    struct addrinfo hints, *res;
    struct sockaddr_in6 *ipv6;
    struct sockaddr_ll device;
    struct ifreq ifr;
    void *tmp;

    // Allocate memory for various arrays.

	tmp = (unsigned char *) malloc (6 * sizeof (unsigned char));
	if (tmp != NULL)
	{
		src_mac = tmp;
	}
	else
	{
		fprintf (stderr, "ERROR: Cannot allocate memory for array 'src_mac'.\n");
		exit (EXIT_FAILURE);
	}
	memset (src_mac, 0, 6 * sizeof (unsigned char));

	tmp = (unsigned char *) malloc (6 * sizeof (unsigned char));
	if (tmp != NULL)
	{
		dst_mac = tmp;
	}
	else
	{
		fprintf (stderr, "ERROR: Cannot allocate memory for array 'dst_mac'.\n");
		exit (EXIT_FAILURE);
	}
	memset (dst_mac, 0, 6 * sizeof (unsigned char));

	tmp = (unsigned char *) malloc (IP_MAXPACKET * sizeof (unsigned char));
	if (tmp != NULL)
	{
		ether_frame = tmp;
	}
	else
	{
		fprintf (stderr, "ERROR: Cannot allocate memory for array 'ether_frame'.\n");
		exit (EXIT_FAILURE);
	}
	memset (ether_frame, 0, IP_MAXPACKET * sizeof (unsigned char));

	tmp = (char *) malloc (40 * sizeof (char));
	if (tmp != NULL)
	{
		interface = tmp;
	}
	else
	{
		fprintf (stderr, "ERROR: Cannot allocate memory for array 'interface'.\n");
		exit (EXIT_FAILURE);
	}
	memset (interface, 0, 40 * sizeof (char));

	tmp = (char *) malloc (40 * sizeof (char));
	if (tmp != NULL)
	{
		target = tmp;
	}
	else
	{
		fprintf (stderr, "ERROR: Cannot allocate memory for array 'target'.\n");
		exit (EXIT_FAILURE);
	}
	memset (target, 0, 40 * sizeof (char));

	tmp = (char *) malloc (40 * sizeof (char));
	if (tmp != NULL)
	{
		src_ip = tmp;
	}
	else
	{
		fprintf (stderr, "ERROR: Cannot allocate memory for array 'src_ip'.\n");
		exit (EXIT_FAILURE);
	}
	memset (src_ip, 0, 40 * sizeof (char));

	tmp = (char *) malloc (40 * sizeof (char));
	if (tmp != NULL) {
	dst_ip = tmp;
	} else {
	fprintf (stderr, "ERROR: Cannot allocate memory for array 'dst_ip'.\n");
	exit (EXIT_FAILURE);
	}
	memset (dst_ip, 0, 40 * sizeof (char));


	// Interface to send packet through.
	strcpy (interface, "tun0");

	// Submit request for a socket descriptor to look up interface.
	if ((sd = socket (PF_PACKET, SOCK_RAW, htons (ETH_P_ALL))) < 0) {
	perror ("socket() failed to get socket descriptor for using ioctl() ");
	exit (EXIT_FAILURE);
	}

	// Use ioctl() to look up interface name and get its MAC address.
	memset (&ifr, 0, sizeof (ifr));
	snprintf (ifr.ifr_name, sizeof (ifr.ifr_name), "%s", interface);
	if (ioctl (sd, SIOCGIFHWADDR, &ifr) < 0) {
	perror ("ioctl() failed to get source MAC address ");
	return (EXIT_FAILURE);
	}
	close (sd);

	// Copy source MAC address.
	memcpy (src_mac, ifr.ifr_hwaddr.sa_data, 6);

	// Find interface index from interface name and store index in
	// struct sockaddr_ll device, which will be used as an argument of sendto().
	if ((device.sll_ifindex = if_nametoindex (interface)) == 0) {
	perror ("if_nametoindex() failed to obtain interface index ");
	exit (EXIT_FAILURE);
	}
	//printf ("Index for interface %s is %i\n", interface, device.sll_ifindex);

	// Set destination MAC address: you need to fill these out
	dst_mac[0] = 0xff;
	dst_mac[1] = 0xff;
	dst_mac[2] = 0xff;
	dst_mac[3] = 0xff;
	dst_mac[4] = 0xff;
	dst_mac[5] = 0xff;

	// Source IPv6 address: you need to fill this out
	strcpy (src_ip, src);

	// Destination URL or IPv6 address: you need to fill this out
	strcpy (target, dest);

	// Fill out hints for getaddrinfo().
	memset (&hints, 0, sizeof (struct addrinfo));
	hints.ai_family = AF_INET6;
	hints.ai_socktype = SOCK_RAW;
	hints.ai_flags = hints.ai_flags | AI_CANONNAME;

	// Resolve target using getaddrinfo().
	if ((status = getaddrinfo (target, NULL, &hints, &res)) != 0) {
	fprintf (stderr, "getaddrinfo() failed: %s\n", gai_strerror (status));
	exit (EXIT_FAILURE);
	}

	ipv6 = (struct sockaddr_in6 *) res->ai_addr;
	tmp = &(ipv6->sin6_addr);
	if (inet_ntop (AF_INET6, tmp, dst_ip, 40) == NULL) {
	status = errno;
	fprintf (stderr, "inet_ntop() failed.\nError message: %s", strerror (status));
	exit (EXIT_FAILURE);
	}
	freeaddrinfo (res);

	// Fill out sockaddr_ll.
	device.sll_family = AF_PACKET;
	memcpy (device.sll_addr, src_mac, 6);
	device.sll_halen = htons (6);

	// IPv6 header

	// IPv6 version (4 bits), Traffic class (8 bits), Flow label (20 bits)
	iphdr.ip6_flow = htonl ((6 << 28) | (0 << 20) | 0);

	// Payload length (16 bits): TCP header + TCP data
	iphdr.ip6_plen = htons (size);

	// Next header (8 bits): 6 for TCP
	iphdr.ip6_nxt = IPPROTO_TCP;

	// Hop limit (8 bits): default to maximum value
	iphdr.ip6_hops = 255;

	// Source IPv6 address (128 bits)
	if ((status = inet_pton (AF_INET6, src_ip, &(iphdr.ip6_src))) != 1) {
	fprintf (stderr, "inet_pton() failed.\nError message: %s", strerror (status));
	exit (EXIT_FAILURE);
	}

	// Destination IPv6 address (128 bits)
	if ((status = inet_pton (AF_INET6, dst_ip, &(iphdr.ip6_dst))) != 1) {
	fprintf (stderr, "inet_pton() failed.\nError message: %s", strerror (status));
	exit (EXIT_FAILURE);
	}

	// Fill out ethernet frame header.

	// Ethernet frame length = ethernet data (IP header + TCP header + TCP data)
	frame_length = IP6_HDRLEN + size;

	// IPv6 header
	memcpy (ether_frame, &iphdr, IP6_HDRLEN);

	// DATA
	memcpy (ether_frame + IP6_HDRLEN, buffer, size);

	// Submit request for a raw socket descriptor.
	if ((sd = socket (PF_PACKET, SOCK_RAW, htons (ETH_P_ALL))) < 0) {
	perror ("socket() failed ");
	exit (EXIT_FAILURE);
	}

	// Send ethernet frame to socket.
	if ((bytes = sendto (sd, ether_frame, frame_length, 0, (struct sockaddr *) &device, sizeof (device))) <= 0) {
	perror ("sendto() failed");
	exit (EXIT_FAILURE);
	}

	// Close socket descriptor.
	close (sd);

	// Free allocated memory.
	free (src_mac);
	free (dst_mac);
	free (ether_frame);
	free (interface);
	free (target);
	free (src_ip);
	free (dst_ip);

	return 0;
}
int sendIPV4Packet(char *buffer, int size,char* src, char* dest)
{
	int i, status, sd, *ip_flags;
	  const int on = 1;
	  char *interface, *target, *src_ip, *dst_ip;
	  struct ip iphdr;
	  struct tcphdr tcphdr;
	  int payloadlen;
	  unsigned char *tcp_flags, *packet;
	  struct addrinfo hints, *res;
	  struct sockaddr_in *ipv4, sin;
	  struct ifreq ifr;
	  void *tmp;

	  // Allocate memory for various arrays.
	  tmp = (unsigned char *) malloc (IP_MAXPACKET * sizeof (unsigned char));
	  if (tmp != NULL) {
	    packet = tmp;
	  } else {
	    fprintf (stderr, "ERROR: Cannot allocate memory for array 'packet'.\n");
	    exit (EXIT_FAILURE);
	  }
	  memset (packet, 0, IP_MAXPACKET * sizeof (unsigned char));

	  tmp = (char *) malloc (40 * sizeof (char));
	  if (tmp != NULL) {
	    interface = tmp;
	  } else {
	    fprintf (stderr, "ERROR: Cannot allocate memory for array 'interface'.\n");
	    exit (EXIT_FAILURE);
	  }
	  memset (interface, 0, 40 * sizeof (char));

	  tmp = (char *) malloc (40 * sizeof (char));
	  if (tmp != NULL) {
	    target = tmp;
	  } else {
	    fprintf (stderr, "ERROR: Cannot allocate memory for array 'target'.\n");
	    exit (EXIT_FAILURE);
	  }
	  memset (target, 0, 40 * sizeof (char));

	  tmp = (char *) malloc (16 * sizeof (char));
	  if (tmp != NULL) {
	    src_ip = tmp;
	  } else {
	    fprintf (stderr, "ERROR: Cannot allocate memory for array 'src_ip'.\n");
	    exit (EXIT_FAILURE);
	  }
	  memset (src_ip, 0, 16 * sizeof (char));

	  tmp = (char *) malloc (16 * sizeof (char));
	  if (tmp != NULL) {
	    dst_ip = tmp;
	  } else {
	    fprintf (stderr, "ERROR: Cannot allocate memory for array 'dst_ip'.\n");
	    exit (EXIT_FAILURE);
	  }
	  memset (dst_ip, 0, 16 * sizeof (char));

	  tmp = (int *) malloc (4 * sizeof (int));
	  if (tmp != NULL) {
	    ip_flags = tmp;
	  } else {
	    fprintf (stderr, "ERROR: Cannot allocate memory for array 'ip_flags'.\n");
	    exit (EXIT_FAILURE);
	  }
	  memset (ip_flags, 0, 4 * sizeof (int));

	  tmp = (unsigned char *) malloc (16 * sizeof (unsigned char));
	  if (tmp != NULL) {
	    tcp_flags = tmp;
	  } else {
	    fprintf (stderr, "ERROR: Cannot allocate memory for array 'tcp_flags'.\n");
	    exit (EXIT_FAILURE);
	  }
	  memset (tcp_flags, 0, 4 * sizeof (unsigned char));

	  // Interface to send packet through.
	  strcpy (interface, "eth0");

	  // Submit request for a socket descriptor to look up interface.
	  if ((sd = socket (AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) {
	    perror ("socket() failed to get socket descriptor for using ioctl() ");
	    exit (EXIT_FAILURE);
	  }

	  // Use ioctl() to look up interface index which we will use to
	  // bind socket descriptor sd to specified interface with setsockopt() since
	  // none of the other arguments of sendto() specify which interface to use.
	  memset (&ifr, 0, sizeof (ifr));
	  snprintf (ifr.ifr_name, sizeof (ifr.ifr_name), "%s", interface);
	  if (ioctl (sd, SIOCGIFINDEX, &ifr) < 0) {
	    perror ("ioctl() failed to find interface ");
	    return (EXIT_FAILURE);
	  }
	  close (sd);
	  // Source IPv4 address: you need to fill this out
	  strcpy (src_ip, src);

	  // Destination URL or IPv4 address: you need to fill this out
	  strcpy (target, dest);

	  // Fill out hints for getaddrinfo().
	  memset (&hints, 0, sizeof (struct addrinfo));
	  hints.ai_family = AF_INET;
	  hints.ai_socktype = SOCK_STREAM;
	  hints.ai_flags = hints.ai_flags | AI_CANONNAME;

	  // Resolve target using getaddrinfo().
	  if ((status = getaddrinfo (target, NULL, &hints, &res)) != 0) {
	    fprintf (stderr, "getaddrinfo() failed: %s\n", gai_strerror (status));
	    exit (EXIT_FAILURE);
	  }
	  ipv4 = (struct sockaddr_in *) res->ai_addr;
	  tmp = &(ipv4->sin_addr);
	  if (inet_ntop (AF_INET, tmp, dst_ip, 16) == NULL) {
	    status = errno;
	    fprintf (stderr, "inet_ntop() failed.\nError message: %s", strerror (status));
	    exit (EXIT_FAILURE);
	  }
	  freeaddrinfo (res);

	  // IPv4 header

	  // IPv4 header length (4 bits): Number of 32-bit words in header = 5
	  iphdr.ip_hl = IP4_HDRLEN / sizeof (unsigned long int);

	  // Internet Protocol version (4 bits): IPv4
	  iphdr.ip_v = 4;

	  // Type of service (8 bits)
	  iphdr.ip_tos = 0;

	  // Total length of datagram (16 bits): IP header + TCP header + TCP data
	  iphdr.ip_len = htons (IP4_HDRLEN + size);

	  // ID sequence number (16 bits): unused, since single datagram
	  iphdr.ip_id = htons (0);

	  // Flags, and Fragmentation offset (3, 13 bits): 0 since single datagram

	  // Zero (1 bit)
	  ip_flags[0] = 0;

	  // Do not fragment flag (1 bit)
	  ip_flags[1] = 1;

	  // More fragments following flag (1 bit)
	  ip_flags[2] = 0;

	  // Fragmentation offset (13 bits)
	  ip_flags[3] = 0;

	  iphdr.ip_off = htons ((ip_flags[0] << 15)
	                      + (ip_flags[1] << 14)
	                      + (ip_flags[2] << 13)
	                      +  ip_flags[3]);

	  // Time-to-Live (8 bits): default to maximum value
	  iphdr.ip_ttl = 255;

	  // Transport layer protocol (8 bits): 6 for TCP
	  iphdr.ip_p = IPPROTO_TCP;

	  // Source IPv4 address (32 bits)
	  if ((status = inet_pton (AF_INET, src_ip, &(iphdr.ip_src))) != 1) {
	    fprintf (stderr, "inet_pton() failed.\nError message: %s", strerror (status));
	    exit (EXIT_FAILURE);
	  }

	  // Destination IPv4 address (32 bits)
	  if ((status = inet_pton (AF_INET, dst_ip, &(iphdr.ip_dst))) != 1) {
	    fprintf (stderr, "inet_pton() failed.\nError message: %s", strerror (status));
	    exit (EXIT_FAILURE);
	  }

	  // IPv4 header checksum (16 bits): set to 0 when calculating checksum
	  iphdr.ip_sum = 0;
	  iphdr.ip_sum = checksum ((unsigned short int *) &iphdr, IP4_HDRLEN);


	  // First part is an IPv4 header.
	  memcpy (packet, &iphdr, IP4_HDRLEN);

	  // Next part of packet is upper layer protocol header.
	  memcpy ((packet + IP4_HDRLEN), buffer,size );

	  // The kernel is going to prepare layer 2 information (ethernet frame header) for us.
	  // For that, we need to specify a destination for the kernel in order for it
	  // to decide where to send the raw datagram. We fill in a struct in_addr with
	  // the desired destination IP address, and pass this structure to the sendto() function.
	  memset (&sin, 0, sizeof (struct sockaddr_in));
	  sin.sin_family = AF_INET;
	  sin.sin_addr.s_addr = iphdr.ip_dst.s_addr;

	  // Submit request for a raw socket descriptor.
	  if ((sd = socket (AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) {
	    perror ("socket() failed ");
	    exit (EXIT_FAILURE);
	  }

	  // Set flag so socket expects us to provide IPv4 header.
	  if (setsockopt (sd, IPPROTO_IP, IP_HDRINCL, &on, sizeof (on)) < 0) {
	    perror ("setsockopt() failed to set IP_HDRINCL ");
	    exit (EXIT_FAILURE);
	  }

	  // Bind socket to interface index.
	  if (setsockopt (sd, SOL_SOCKET, SO_BINDTODEVICE, &ifr, sizeof (ifr)) < 0) {
	    perror ("setsockopt() failed to bind to interface ");
	    exit (EXIT_FAILURE);
	  }

	  // Send packet.
	  i = sendto (sd, packet, IP4_HDRLEN + size, 0, (struct sockaddr *) &sin, sizeof (struct sockaddr));
	  printf("SIZE SENT: %d\n",i);
	  if (i < 0)  {
	    perror ("sendto() failed ");
	    exit (EXIT_FAILURE);
	  }

	  // Close socket descriptor.
	  close (sd);

	  // Free allocated memory.
	  free (packet);
	  free (interface);
	  free (target);
	  free (src_ip);
	  free (dst_ip);
	  free (ip_flags);
	  free (tcp_flags);

	  return 0;
}
unsigned short int checksum (unsigned short int *addr, int len)
{
  int nleft = len;
  int sum = 0;
  unsigned short int *w = addr;
  unsigned short int answer = 0;

  while (nleft > 1) {
    sum += *w++;
    nleft -= sizeof (unsigned short int);
  }

  if (nleft == 1) {
    *(unsigned char *) (&answer) = *(unsigned char *) w;
    sum += answer;
  }

  sum = (sum >> 16) + (sum & 0xFFFF);
  sum += (sum >> 16);
  answer = ~sum;
  return (answer);
}

char* toHex(int num)
{
	char* buffer;
	buffer = (char *) calloc(16,sizeof(char));
	sprintf(buffer,"%02X",num);
	return buffer;
}

int toDec(char one, char two)
{
	return (convert(one) * 16) + convert(two);
}

int convert(char c)
{
	if(48 <= c && c <= 57)
			c -= 48;
		else if(65 <= c && c <= 70)
			c-=55; //remove letters (-65) add 10 for A to be 10 (+10) = -55
		else if(97 <= c && c <= 102)
			c -= 87; //remove letters (-97) add 10 for a to be 10 (+10) = -55
	return c;
}

char* translate(int version, char* myaddr) //version indicates the current version not the target!
{
	char* result;
	char* buffer;
	int chunk;
	char* val;
	char *addr;
	addr = calloc(strlen(myaddr),sizeof(char));
	result = (char *) calloc(100,sizeof(char));
	strcpy(addr,myaddr);

	if(version == 4)
	{
		chunk = atoi(strtok(addr,"."));
		strcat(result,toHex(chunk));

		chunk = atoi(strtok(NULL,"."));
		strcat(result,toHex(chunk));
		strcat(result,"::");

		chunk = atoi(strtok(NULL,"."));
		strcat(result,toHex(chunk));

		chunk = atoi(strtok(NULL,"."));
		strcat(result,toHex(chunk));

		return cleanIPV6(result);
	}
	else if(version == 6)
	{
		val = strtok(addr,":");
		buffer = (char *) calloc(3,sizeof(char));
		chunk = toDec(val[0],val[1]);
		sprintf(buffer,"%d",chunk);
		strcat(result,buffer);
		strcat(result,".");

		buffer = (char *) calloc(3,sizeof(char));
		chunk = toDec(val[2],val[3]);
		sprintf(buffer,"%d",chunk);
		strcat(result,buffer);
		strcat(result,".");

		val = strtok(NULL,":");
		buffer = (char *) calloc(3,sizeof(char));
		chunk = toDec(val[0],val[1]);
		sprintf(buffer,"%d",chunk);
		strcat(result,buffer);
		strcat(result,".");

		buffer = (char *) calloc(3,sizeof(char));
		chunk = toDec(val[2],val[3]);
		sprintf(buffer,"%d",chunk);
		strcat(result,buffer);
		return result;
	}
}
char* cleanIPV6(char* addr)
{
	char* result;
	char* buffer;
	int chunk;
	char *val1, *val2;
	char* buff;
	int i;
	int count = 1;
	result = (char *) calloc(16,sizeof(char));
	val1 = strtok(addr,":");
	val2 = (char*) malloc(sizeof(char));
	while(val2 != NULL)
	{
		val2 = strtok(NULL,":");
		if(strlen(val1) < 4)
		{
			for(i = 0; i < 4 - strlen(val1); i++)
			{
				strcat(result,"0");
			}
			strcat(result,val1);
			strcat(result,":");
		}
		else
		{
			if( val2 == NULL)
			{
				strcat(result,":");
				for(i = 0; i < strlen(val1); i++)
				{
					if(val1[i] != '0')
					{
						buff = (char *) calloc(2,sizeof(char));
						buff[0] = val1[i];
						buff[1] = '\0';
						strcat(result,buff);
					}
				}
			}
			else
			{
				strcat(result,val1);
				strcat(result,":");
			}
		}
		if(val2 != NULL)
			strcpy(val1,val2);
		count++;
	}
	return result;

}


