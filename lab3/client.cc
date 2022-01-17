#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h> 
#include <string>
#include<iostream>
#include <fstream>
using namespace std;
int main(int argc, char* argv[])
{    
    int CreateSocket = 0,n = 0;    
    char dataReceived[64];    
    string data = "";
    string address=argv[1];
    FILE *fp;
    address.append(".txt");
    fp=fopen(address.data(),"w+b,ccs=UTF-8");
    struct sockaddr_in ipOfServer;     
    memset(dataReceived, '0' ,sizeof(dataReceived));     
    if((CreateSocket = socket(AF_INET, SOCK_STREAM, 0))< 0)    
    {        
        printf("Socket not created \n");        
        return 1;    
        }     
    struct hostent* server;
    int count=0;
    // server = gethostbyname(argv[2]);
    ipOfServer.sin_family = AF_INET;    
    ipOfServer.sin_port = htons(2017); 
    // bcopy((char*) server->h_addr, (char*) &ipOfServer.sin_addr.s_addr, server->h_length);   
    ipOfServer.sin_addr.s_addr = inet_addr("10.0.0.1");     
    if(connect(CreateSocket, (struct sockaddr *)&ipOfServer, sizeof(ipOfServer))<0)    
    {       
        printf("Connection failed due to port and ip problems\n");        
        return 1;    
        }     
    while(1)    
    {     
        if((n=recv(CreateSocket, dataReceived, sizeof(dataReceived),0))<=0)
        {
            break;
        }
        // if ((n=read(CreateSocket,dataReceived,1)<=0)) break;
        // ipOfServer.sin_family = AF_INET;    
        // ipOfServer.sin_port = htons(2017); 
        // bcopy((char*) server->h_addr, (char*) &ipOfServer.sin_addr.s_addr, server->h_length); 
        // if(connect(CreateSocket, (struct sockaddr *)&ipOfServer, sizeof(ipOfServer))<0)    
        // {       
        // printf("Connection failed due to port and ip problems\n");        
        // return 1;    
        // }        
        if(fputs(dataReceived, stdout) == EOF)        
        {            
            printf("\nStandard output error");        
        }         
        if(n>0&&dataReceived[0]!=NULL)
        {   count++;
            if(fwrite(dataReceived,sizeof(char),n,fp)<n) 
            {
                printf("not put in\n");
                break;
            }
            printf("line %d receive %d bytes of data :%s \n",count,n,dataReceived); 
            // data.append(dataReceived);//save the result
        }
        bzero(dataReceived,64);
    }
    // fputs(data.data(),fp);
    if( n < 0)    
        {        
            printf("Standard input error \n");    
        }     
    fclose(fp);
    close(CreateSocket);
    return 0;
    }