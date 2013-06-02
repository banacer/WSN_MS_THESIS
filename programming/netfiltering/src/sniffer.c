#include "sniffer.h"
//HI HI
struct sockaddr_in source,dest;
int tcp = 0, udp = 0, icmp = 0, others = 0, igmp = 0,total = 0;
int i,j;
char map[10][2][100];
int map_size;

int main()
{
	FILE* map_file;
    int saddr_size , data_size;
    struct sockaddr saddr;
    unsigned char *buffer = (unsigned char *) malloc(65536);


    printf("Starting...\n");
    map_file = fopen("data/ipmapping.dat","r");
    i = 0;
    while(!feof(map_file))
	{
    	fscanf(map_file,"%s , %s",map[i][0],map[i][1]);
    	i++;
	}
    map_size = i;

    int sock_raw = socket( PF_PACKET, SOCK_PACKET , htons(ETH_P_ALL)) ;

    if(sock_raw < 0)
    {
        perror("Socket Error");
        return 1;
    }
    while(1)
    {
        saddr_size = sizeof(saddr);
        //Receive a packet
        data_size = recvfrom(sock_raw , buffer , 65536 , 0 , &saddr , (socklen_t*)&saddr_size);
        if(data_size < 0 )
        {
            printf("Recvfrom error , failed to get packets\n");
            return 1;
        }
        //Now process the packet
        ProcessPacket(buffer , data_size);
    }
    close(sock_raw);
    free(buffer);
    printf("Finished");
    return 0;
}

void ProcessPacket(unsigned char* buffer, int size)
{
	uint8_t protocol;
	char* addr;
	short val;
    //Get the IP Header part of this packet , excluding the ethernet header
    struct iphdr *iph = (struct iphdr*)(buffer + sizeof(struct ethhdr));
    struct ip6_hdr *iph6 = (struct ip6_hdr*)(buffer + sizeof(struct ethhdr));
    struct sockaddr_in *in;
    struct sockaddr_in6 *in6;
    in = (struct sockaddr_in *) malloc(sizeof(struct sockaddr_in));
	in->sin_addr.s_addr = iph->saddr;
    if(iph->version == 6)
    {
    	protocol = iph6->ip6_nxt;

    	printf("\n protocol: %d\n",protocol);
    	if(protocol != 0)
    	{
    		printf("\nBEGIN\n\n");
    		for(i = 0; i < size; i++)
    		{
    			if(i % 8 == 0)
    			    printf("\n");

    			val = *(buffer + i * sizeof(char)+ + sizeof(struct ethhdr));
   				printf("%x  ",val);
    		}
    		printf("\n\nEND\n\n");
    	}

    }
    else
    {
    	protocol = iph->protocol;
    }
    ++total;

    switch (protocol) //Check the Protocol and do accordingly...
    {
        case 1:  //ICMP Protocol
            ++icmp;
            break;

        case 2:  //IGMP Protocol
            ++igmp;
            break;

        case 6:
        case 17://TCP AND UDP Protocol
            ++tcp;
            ++udp;
            if(iph->version == 4)
            {
            	in = (struct sockaddr_in*) (buffer);
            	buffer = (buffer  + sizeof(struct ethhdr) + IP4_HDRLEN);
            	size = size - sizeof(struct ethhdr) - IP4_HDRLEN;
            	in->sin_addr.s_addr = iph->saddr;
            	if(strcasecmp("10.50.0.206",inet_ntoa(in->sin_addr)) == 0)
            		addr = "fec0::1";
            	else
            		addr = NULL;
            	if(addr != NULL)
            	{
            		sendIPV6Packet(buffer,size,"fec0::1");
            	}
            }
            else
            {
            	buffer = (buffer  + sizeof(struct ethhdr) + IP6_HDRLEN);
            	size = size - sizeof(struct ethhdr) - IP6_HDRLEN;
            	in6 = (struct sockaddr_in6 *) malloc(sizeof(struct sockaddr_in6));
            	in6->sin6_addr.__in6_u = iph6->ip6_src.__in6_u;
            	addr = calloc(INET6_ADDRSTRLEN,sizeof(char));
            	inet_ntop(AF_INET6, &(in6->sin6_addr), addr, INET6_ADDRSTRLEN);
            	printf("\nYOU ARE HERE %s !\n",addr);
            	if(strcmp("fec0::1",addr) == 0)
            		addr = "10.50.0.206";
            	else
            		addr = "10.50.0.206";
            	if(addr != NULL)
            	{

            		sendIPV4Packet(buffer,size,"10.50.0.206");
            	}
            }
            break;

        default: //Some Other Protocol like ARP etc.
            ++others;
            break;
    }
    //printf("TCP : %d   UDP : %d   ICMP : %d   IGMP : %d   Others : %d   Total : %d\r", tcp , udp , icmp , igmp , others , total);
}

int sendIPV6Packet(char* buffer,int size, char *dest)
{
	int i, status, frame_length, sd, bytes;
    char *interface, *target, *src_ip, *dst_ip;
    struct ip6_hdr iphdr;
    struct tcphdr tcphdr;
    char *payload;
    int payloadlen;
    unsigned char *tcp_flags, *src_mac, *dst_mac, *ether_frame;
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
	strcpy (src_ip, "fec0::64");

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
int sendIPV4Packet(char *buffer, int size, char* dest)
{
	  int i, status, frame_length, sd, bytes, *ip_flags;
	  char *interface, *target, *src_ip, *dst_ip;
	  struct ip iphdr;
	  struct tcphdr tcphdr;
	  char *payload;
	  int payloadlen;
	  unsigned char *tcp_flags, *src_mac, *dst_mac, *ether_frame;
	  struct addrinfo hints, *res = NULL;
	  struct sockaddr_in *ipv4;
	  struct sockaddr_ll device;
	  struct ifreq ifr;
	  void *tmp;
	  // Allocate memory for various arrays.

	  tmp = (unsigned char *) malloc (6 * sizeof (unsigned char));
	  if (tmp != NULL) {
	    src_mac = tmp;
	  } else {
	    fprintf (stderr, "ERROR: Cannot allocate memory for array 'src_mac'.\n");
	    exit (EXIT_FAILURE);
	  }
	  memset (src_mac, 0, 6 * sizeof (unsigned char));

	  tmp = (unsigned char *) malloc (6 * sizeof (unsigned char));
	  if (tmp != NULL) {
	    dst_mac = tmp;
	  } else {
	    fprintf (stderr, "ERROR: Cannot allocate memory for array 'dst_mac'.\n");
	    exit (EXIT_FAILURE);
	  }
	  memset (dst_mac, 0, 6 * sizeof (unsigned char));

	  tmp = (unsigned char *) malloc (IP_MAXPACKET * sizeof (unsigned char));
	  if (tmp != NULL) {
	    ether_frame = tmp;
	  } else {
	    fprintf (stderr, "ERROR: Cannot allocate memory for array 'ether_frame'.\n");
	    exit (EXIT_FAILURE);
	  }
	  memset (ether_frame, 0, IP_MAXPACKET * sizeof (unsigned char));

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

	  // Maximum TCP payload size = 65535 - IPv4 header (20 bytes) - TCP header (20 bytes)
	  tmp = (char *) malloc ((IP_MAXPACKET - IP4_HDRLEN - TCP_HDRLEN) * sizeof (char));
	  if (tmp != NULL) {
	    payload = tmp;
	  } else {
	    fprintf (stderr, "ERROR: Cannot allocate memory for array 'payload'.\n");
	    exit (EXIT_FAILURE);
	  }
	  memset (payload, 0, (IP_MAXPACKET - IP4_HDRLEN - TCP_HDRLEN) * sizeof (char));

	  // Interface to send packet through.
	  strcpy (interface, "eth0");

	  // Submit request for a socket descriptor to look up interface.
	  if ((sd = socket (AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) {
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

	  // Set destination MAC address: you need to fill this out
	  dst_mac[0] = 0xff;
	  dst_mac[1] = 0xff;
	  dst_mac[2] = 0xff;
	  dst_mac[3] = 0xff;
	  dst_mac[4] = 0xff;
	  dst_mac[5] = 0xff;

	  // Source IPv4 address: you need to fill this out
	  strcpy (src_ip, "10.50.1.45");

	  // Destination URL or IPv4 address: you need to fill this out
	  strcpy (target, dest);

	  // Fill out hints for getaddrinfo().
	  memset (&hints, 0, sizeof (struct addrinfo));
	  hints.ai_family = AF_INET;
	  hints.ai_socktype = SOCK_RAW;
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

	  // Fill out sockaddr_ll.
	  device.sll_family = AF_PACKET;
	  device.sll_protocol = htons (ETH_P_IP);
	  memcpy (device.sll_addr, dst_mac, 6);
	  device.sll_halen = htons (6);

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

	  // Fill out ethernet frame header.

	    // Ethernet frame length = ethernet header (MAC + MAC + ethernet type) + ethernet data (IP header + TCP header + TCP options)
	    frame_length = 6 + 6 + 2 + IP4_HDRLEN + size;

	    // Destination and Source MAC addresses
	    memcpy (ether_frame, dst_mac, 6);
	    memcpy (ether_frame + 6, src_mac, 6);

	    // Next is ethernet type code (ETH_P_IP for IPv4).
	    // http://www.iana.org/assignments/ethernet-numbers
	    ether_frame[12] = ETH_P_IP / 256;
	    ether_frame[13] = ETH_P_IP % 256;

	    // Next is ethernet frame data (IPv4 header + TCP header).

	    // IPv4 header
	    memcpy (ether_frame + 14, &iphdr, IP4_HDRLEN);

	    // TCP header
	    memcpy (ether_frame + 14 + IP4_HDRLEN, buffer, size);

	  // Open raw socket descriptor.
	  if ((sd = socket (PF_PACKET, SOCK_RAW, htons (ETH_P_ALL))) < 0) {
	    perror ("socket() failed ");
	    exit (EXIT_FAILURE);
	  }

	  // Send ethernet frame to socket.
	  if ((bytes = sendto (sd, ether_frame, frame_length, 0, (struct sockaddr *) &device, sizeof (device))) <= 0) {
	    perror ("sendto() failed");
	    exit (EXIT_FAILURE);
	  }

	  close (sd);

	  // Free allocated memory.
	  free (src_mac);
	  free (dst_mac);
	  free (ether_frame);
	  free (interface);
	  free (target);
	  free (src_ip);
	  free (dst_ip);
	  free (ip_flags);
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

char* getIPAddr(char* addr , int version)
{
	int i;
	if(version == 4)
	{
		for(i = 0; i < map_size; i++)
		{
			if(strcmp(addr,map[i][0]) == 0)
				return map[i][1];
		}
	}

	if(version == 6)
	{
		for(i = 0; i < map_size; i++)
		{
			if(strcmp(addr,map[i][1]) == 0)
				return map[i][0];
		}
	}
	return NULL;
}
char* convert6to4(char* addr, int len)
{
	return NULL;
}

char* convert4to6(char*addr, int len)
{
	return NULL;
}

}

