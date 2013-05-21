/*
 * "Copyright (c) 2008 The Regents of the University  of California.
 * All rights reserved."
 *
 * Permission to use, copy, modify, and distribute this software and its
 * documentation for any purpose, without fee, and without written agreement is
 * hereby granted, provided that the above copyright notice, the following
 * two paragraphs and the author appear in all copies of this software.
 *
 * IN NO EVENT SHALL THE UNIVERSITY OF CALIFORNIA BE LIABLE TO ANY PARTY FOR
 * DIRECT, INDIRECT, SPECIAL, INCIDENTAL, OR CONSEQUENTIAL DAMAGES ARISING OUT
 * OF THE USE OF THIS SOFTWARE AND ITS DOCUMENTATION, EVEN IF THE UNIVERSITY OF
 * CALIFORNIA HAS BEEN ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * THE UNIVERSITY OF CALIFORNIA SPECIFICALLY DISCLAIMS ANY WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS FOR A PARTICULAR PURPOSE.  THE SOFTWARE PROVIDED HEREUNDER IS
 * ON AN "AS IS" BASIS, AND THE UNIVERSITY OF CALIFORNIA HAS NO OBLIGATION TO
 * PROVIDE MAINTENANCE, SUPPORT, UPDATES, ENHANCEMENTS, OR MODIFICATIONS."
 *
 */

#include <IPDispatch.h>
#include <lib6lowpan.h>
#include <ip.h>
#include <lib6lowpan.h>
#include <ip.h>
#include <string.h>
#include <stdlib.h>
#include "UDPReport.h"
#include "PrintfUART.h"
#include <IPDispatch.h>
#include <lib6lowpan.h>
#include <ip.h>

#define REPORT_PERIOD 75L

module TCPEchoP {
  uses {
    interface Boot;
    interface SplitControl as RadioControl;	
    interface UDP as Echo;
    interface UDP as Status;
    interface Tcp as TcpEcho;	
    interface Leds;
    interface Tcp as TcpClient;
    interface Timer<TMilli> as StatusTimer;
    interface Timer<TMilli> as sensingTimer;
   	interface IPAddress;
    interface Statistics<ip_statistics_t> as IPStats;
    interface Statistics<route_statistics_t> as RouteStats;
    interface Statistics<icmp_statistics_t> as ICMPStats;
    interface Statistics<udp_statistics_t> as UDPStats;
    
    interface Random;
    interface Read<uint8_t> as Sensors;

  }

} implementation {

  bool timerStarted;
  bool open = FALSE;
  nx_struct udp_report stats;
  struct sockaddr_in6 route_dest;
  struct sockaddr_in6 dest;  
#ifndef SIM
#define CHECK_NODE_ID
#else
#define CHECK_NODE_ID if (TOS_NODE_ID == BASESTATION_ID) return
#endif

  event void Boot.booted() {
  	int client_port;
  	char addr[] = "fec0::64";
  	char tcpBuf[100];
    CHECK_NODE_ID;
    call RadioControl.start();
    timerStarted = FALSE;
    	
    call IPStats.clear();
    call RouteStats.clear();
    call ICMPStats.clear();
    printfUART_init();	

#ifdef REPORT_DEST
    route_dest.sin6_port = hton16(7000);
    inet_pton6(REPORT_DEST, &route_dest.sin6_addr);
    call StatusTimer.startOneShot(call Random.rand16() % (1024 * REPORT_PERIOD));
#endif
	
    dbg("Boot", "booted: %i\n", TOS_NODE_ID);
    call Echo.bind(7);
    call TcpEcho.bind(7);
    call Status.bind(7001);
    call sensingTimer.startPeriodic(10000);
    call IPAddress.getPublicAddr();
    inet_pton6(addr, &dest.sin6_addr);
    // set destination port
    dest.sin6_port = htons(8080);
    client_port = call Random.rand16();
    call TcpClient.bind(client_port);
    call TcpClient.connect(&dest, tcpBuf, 100);  
    open = TRUE;       
  }

  event void RadioControl.startDone(error_t e) {

  }

  event void RadioControl.stopDone(error_t e) {

  }

  event void Status.recvfrom(struct sockaddr_in6 *from, void *data, 
                             uint16_t len, struct ip_metadata *meta) {

  }

  event void Echo.recvfrom(struct sockaddr_in6 *from, void *data, 
                           uint16_t len, struct ip_metadata *meta) {
    CHECK_NODE_ID;
    call Echo.sendto(from, data, len);
  }

  enum {
    STATUS_SIZE = sizeof(ip_statistics_t) + 
    sizeof(route_statistics_t) +
    sizeof(icmp_statistics_t) + sizeof(udp_statistics_t),
  };


  event void StatusTimer.fired() {

    if (!timerStarted) {
      call StatusTimer.startPeriodic(1024 * REPORT_PERIOD);
      timerStarted = TRUE;
    }

    stats.seqno++;
    stats.sender = TOS_NODE_ID;

    call IPStats.get(&stats.ip);
    call RouteStats.get(&stats.route);
    call ICMPStats.get(&stats.icmp);
    call UDPStats.get(&stats.udp);

    call Status.sendto(&route_dest, &stats, sizeof(stats));
  }

  /* 
   * Example code for setting up a TCP echo socket.
   */

  bool sock_connected = FALSE;
  char tcp_buf[150];

  event bool TcpEcho.accept(struct sockaddr_in6 *from,
                            void **tx_buf, int *tx_buf_len) {
    *tx_buf = tcp_buf;
    *tx_buf_len = 150;
    return TRUE;
  }
  event void TcpEcho.connectDone(error_t e) {
    
  }
  event void TcpEcho.recv(void *payload, uint16_t len) {
  	int led = atoi(strtok((char *) payload, " "));
  	int status = atoi(strtok(NULL, " "));
  	char * msg = "you are here";
  	
  	//call TcpEcho.send(status,strlen(status));
  	
  	if(status == 1)
  	{  		
      	
  		if(led == 0)
  			call Leds.led0On();
  		if(led == 1)
  			call Leds.led1On();
  		if(led == 2)
  			call Leds.led2On();
  	}
  	else if (status == 0)
  	{
  		if(led == 0)
  			call Leds.led0Off();
  		if(led == 1)
  			call Leds.led1Off();
  		if(led == 2)
  			call Leds.led2Off();
  			
  	}
  }
  event void TcpEcho.closed(error_t e) {   
    call TcpEcho.bind(7);
  }
  event void TcpEcho.acked() {}


	
	 
	 event void Sensors.readDone(error_t result, uint8_t val){
		// TODO Auto-generated method stub
		int device = TOS_NODE_ID;
		int value  = (int) val;
		char dev[10];
		char valu[10];
		char msg[20];
		char final[] = " 1,18\n";
		call Leds.led1Toggle();
		sprintf(dev, "%d", device);
		sprintf(valu, "%d", value);
		
		//msg[0] = ',';
		//strcat(dev,msg);
		//strcat(msg,valu);
		//final[0] = '\n';
		//strcat(valu,final);
		if(open)
		{
			call TcpClient.send((void *)final, strlen(final));
			
		}
		
	}
	
	event void TcpClient.connectDone(error_t e){
		
	}

	event bool TcpClient.accept(struct sockaddr_in6 *from, void **tx_buf, int *tx_buf_len){
		return TRUE;
	}

	event void TcpClient.closed(error_t e){
		open = FALSE;
	}

	event void TcpClient.recv(void *payload, uint16_t len){
		// TODO Auto-generated method stub
	}

	event void TcpClient.acked(){
		
	}
	event void sensingTimer.fired() {		
		call Sensors.read();
   	}
}
