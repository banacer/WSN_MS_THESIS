#include "sender.h"
#include "AM.h"
#include "Serial.h"

 module SenderC
{
	uses interface Leds;
	uses interface Timer<TMilli> as timer;
	uses interface Boot;
	uses interface Packet;
  	uses interface AMPacket;
 	uses interface AMSend;
 	uses interface Receive;
  	uses interface SplitControl as AMControl;  	  
  	uses interface Read<uint16_t>;	
  	
}
implementation
{
	uint16_t counter = 0;
	bool busy = FALSE;
  	message_t pkt;
  	SenderMsg* spkt;
  	ErrorMsg* epkt;
  	
  	event void Boot.booted(){
  		int error;
		call AMControl.start();
		error = call Read.read();
		if(error != 0)
		{		
			epkt = (ErrorMsg*)(call Packet.getPayload(&pkt, sizeof (ErrorMsg)));
			epkt->nodeid = TOS_NODE_ID;
			epkt->error = error;
    		error = call AMSend.send(AM_BROADCAST_ADDR, &pkt, sizeof(ErrorMsg));
    	}
	}
	
	event void AMControl.startDone(error_t error){
		if (error == SUCCESS)
			call timer.startPeriodic(1000);
		else 
      		call AMControl.start();
	}
	
	event void timer.fired(){
		call Leds.led1Toggle();		
	}

	event void AMSend.sendDone(message_t *msg, error_t error){
		if (&pkt == msg)
      		busy = FALSE;
	}

	event void AMControl.stopDone(error_t error){
		// TODO Auto-generated method stub
	}

	event message_t * Receive.receive(message_t *msg, void *payload, uint8_t len){
		return msg;
	}
	
	event void Read.readDone(error_t result, uint16_t val){		
		// TODO Auto-generated method stub
		uint16_t error;
		spkt = (SenderMsg*)(call Packet.getPayload(&pkt, sizeof (SenderMsg)));
		spkt->nodeid = TOS_NODE_ID;
		spkt->consumption = val;    	
    	call Leds.led0Toggle();
    	error = call AMSend.send(AM_BROADCAST_ADDR, &pkt, sizeof(SenderMsg));
    	if (error == SUCCESS)
    	{
    		busy = TRUE;    		
    	}    	
	}
}
