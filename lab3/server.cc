#include <stdio.h> // standard input and output library
#include <stdlib.h> // this includes functions regarding memory allocation
#include <string.h> // contains string functions
#include <errno.h> //It defines macros for reporting and retrieving error conditions through error codes
#include <time.h> //contains various functions for manipulating date and time
#include <unistd.h> //contains various constants
#include <sys/types.h> //contains a number of basic derived types that should be used whenever appropriate
#include <arpa/inet.h> // defines in_addr structure
#include <sys/socket.h> // for socket creation
#include <netinet/in.h> //contains constants and structures needed for internet domain addresses 
#include <sys/select.h>
#include <string>
#include <iostream>
#include <fstream>
using namespace std;
void *send(int clintConnt, char *dataSending, FILE *in)
{
    int count=0;
    int ret;
    while(1)
        {
            bzero(dataSending,sizeof(dataSending));
            if(NULL==fgets(dataSending,512,in)) break;
            printf("here\n");
            ret = send(clintConnt,dataSending,sizeof(dataSending),MSG_MORE);
            count++;
            if(ret <= 0)
            {
                printf("send wrong");
                break;
            }
            if(ret==-1)
            {
                printf("error");
            }
            printf("line %d send %d bytes of data :%s to client %d\n",count,ret,dataSending,clintConnt);
            sleep(0.1);      
        }
    return NULL;
}
int main(){    
    int max_sd,sd,activity; 
    FILE *in;
    pthread_t Pid=0;
    in=fopen("/home/samliu/socket_programming/file.txt","r+b,ccs=UTF-8");
    char dataSending[64]; // Actually this is called packet in Network Communication, which contain data and send through.    
    int clintListn = 0, clintConnt = 0;  
    struct sockaddr_in ipOfServer;
    struct sockaddr_in client_address;
    clintListn = socket(AF_INET, SOCK_STREAM, 0); // creating socket    
    memset(&ipOfServer, '0', sizeof(ipOfServer));    
    memset(dataSending, '0', sizeof(dataSending));    
    ipOfServer.sin_family = AF_INET;    
    ipOfServer.sin_addr.s_addr = htonl(INADDR_ANY);    
    ipOfServer.sin_port = htons(2017);      // this is the port number of running server    
    bind(clintListn, (struct sockaddr*)&ipOfServer , sizeof(ipOfServer));    
    listen(clintListn , 20);  
    while(1)    {        
        printf("\n\nHi,Iam running server.Some Client hit me\n"); // whenever a request from client came. It will be processed here.        
        bzero(dataSending,sizeof(dataSending));
        in=fopen("/home/samliu/socket_programming/file.txt","r+b,css=UTF-8");
        // FD_ZERO(&readfds);
        // FD_SET (clintListn, &readfds);
        // max_sd=clintListn;
        // for(int i=0;i<6;++i)//since there are only 6 clients in the structure
        // {
        //     sd=clientSocket[i];
        //     if(sd>0)
        //     {
        //         FD_SET(sd,&readfds);
        //     }
        //     if(sd>max_sd)
        //         max_sd=sd;
        // }
        // activity=select(max_sd+1,&readfds,NULL,NULL,NULL);
            // if(FD_ISSET(clintListn,&readfds))
            // {
        socklen_t addr_size;
        clintConnt = accept(clintListn, (struct sockaddr*)&client_address, &addr_size);
        int ret,n;
        int count=0;
        // pthread_create(&Pid, NULL, send, NULL);
        // while(1)
        // {
        //     bzero(dataSending,sizeof(dataSending));
        //     if((n=fread(dataSending,sizeof(char),64,in))<=0) break;
        //     printf("here\n");
        //     ret = write(clintConnt,dataSending,sizeof(dataSending));
        //     count++;
        //     if(ret <= 0)
        //     {
        //         printf("send wrong");
        //         break;
        //     }
        //     if(ret==-1)
        //     {
        //         printf("error");
        //     }
        //     printf("line %d send %d bytes of data :%s to client %d\n",count,ret,dataSending,clintConnt);
        //     // sleep(0.1);      
        // }
        while((n=fread(dataSending,sizeof(char),64,in))>0)
        {
            if(send(clintConnt,dataSending,n,0)<0)
            {
                break;
            }
            bzero(dataSending,64);
        }
        printf("send finish");
        
    // }
        close(clintConnt);       
        sleep(1);        
        }
    close (clintListn);           
    return 0;}