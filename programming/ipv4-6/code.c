/*
 * code.c
 *
 *  Created on: Jun 3, 2013
 *      Author: nacerkhalil
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char* toHex(int );
int toDec(char , char );
int convert(char );

int main(int argc, char *argv[])
{
	int i;
	char addr[100];
	char result[100];
	char* buffer;
	int version;
	int chunk;
	char* val;
	version = atoi(argv[1]);
	strcpy(addr,argv[2]);
	//scanf("%d",&version);
	//scanf("%s",addr);

	if(version == 4)
	{
		//strcat(result,"fec0:");
		chunk = atoi(strtok(addr,"."));
		strcat(result,toHex(chunk));

		chunk = atoi(strtok(NULL,"."));
		strcat(result,toHex(chunk));
		strcat(result,"::");

		chunk = atoi(strtok(NULL,"."));
		strcat(result,toHex(chunk));

		chunk = atoi(strtok(NULL,"."));
		strcat(result,toHex(chunk));
		//strcat(result,"::1");

		printf("the result is %s \n",result);


	}
	else if(version == 6)
	{
		val = strtok(addr,":");


		//val = strtok(NULL,":");
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
		//strcat(result,".");

		printf("the result is %s \n",result);







	}
}

char* toHex(int num)
{
	char* buffer;
	buffer = (char *) calloc(2,sizeof(char));
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

