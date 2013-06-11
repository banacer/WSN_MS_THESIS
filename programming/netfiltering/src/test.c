/*
 * test.c
 *
 *  Created on: Jun 6, 2013
 *      Author: banacer
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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
		//printf("val1 = %s , val2 = %s \n",val1,val2);
		if(val2 != NULL)
			strcpy(val1,val2);
		count++;
	}
	printf("result is %s\n", result);
	return result;

}

int main(int argc, char *argv[])
{
	cleanIPV6(argv[1]);
}
