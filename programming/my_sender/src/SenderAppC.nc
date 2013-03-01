configuration SenderAppC
{
	
}
implementation
{
	components MainC, SenderC;
	components LedsC;
	components new TimerMilliC() as timer;
	components ActiveMessageC;
	components new AMSenderC(6);
  	components new AMReceiverC(6);
  	components new SensorMDA300CA();
  	
  		
	SenderC.Boot -> MainC.Boot;
	SenderC.timer -> timer;
	SenderC.Leds -> LedsC;
	SenderC.Packet -> AMSenderC;
  	SenderC.AMPacket -> AMSenderC;
  	SenderC.AMSend -> AMSenderC;
  	SenderC.AMControl -> ActiveMessageC;
  	SenderC.Receive -> AMReceiverC;
  	SenderC.Read -> SensorMDA300CA.ADC_6;
}
