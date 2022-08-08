#include<stdio.h>
#include<math.h>
#include <stdio.h>
#include <malloc.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/fcntl.h>
#include <stdlib.h>
#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>
#include <bluetooth/l2cap.h>
#include <bluetooth/rfcomm.h>
#include <bluetooth/sdp.h>
#include <bluetooth/sdp_lib.h>
#include <errno.h>

#define Maxsize 1500
#define CNT_MIN_LEN 7
#define DISCNT_MIN_LEN 3
#define PUT_MIN_LEN 3
#define GET_MIN_LEN 3
#define STPH_MIN_LEN 4
#define ABT_MIN_LEN 3
#define DEFAULT_MODE 1


void gen_buf(unsigned size,char buff[],unsigned mode,char c)
{
    for (int i = 0; i < size; i++)
        buff[i]=0;
pos: 
    switch (mode)
    {
    case 1://set rand data
        for(int i=0;i<size;i++)
            while(buff[i]==0)
                buff[i]=rand();
        break;
    case 2://set 0
        for(int i=0;i<size;i++)
            buff[i]=0;
        break;
    case 3://set opposite 
        unsigned char mask=1;
        unsigned char res=0;
        if(size<=7&&size>=0)
        {
            mask=mask<<size;
            buff[0]=(buff[0]&(~mask))|(buff[0]^mask);
        }
        break;
    case 4://set given char
        for(int i=0;i<size;i++)
            buff[i]=c;
        break;
    default:
        mode=DEFAULT_MODE;
        goto pos;
    }
}


void length_fuzz(int socket,int connectionId,int op)
{
    char nameBuf[Maxsize]={0};
    unsigned xx=pow(2,15)+1;
    char sendBuf[xx];
    char recvBuf[xx];
    unsigned realLen=0;
    int ieRl=0;
    int minLen=0;
    int len=0;

    gen_buf(20,nameBuf,4,'A');

    switch (op)
    {
    case OBEX_OP_PUT:
        minLen=PUT_MIN_LEN;
        break;
    case OBEX_OP_SETPATH:
        minLen=STPH_MIN_LEN;
        break;
    case OBEX_OP_CONNECT:
        minLen=CNT_MIN_LEN;
        break;
    case OBEX_OP_DISCONNECT:
        minLen=DISCNT_MIN_LEN;
        break;
    case OBEX_OP_GET:
        minLen=GET_MIN_LEN;
        break;
    default:
        break;
    }

    for(len=1;len<=minLen;len++)
    {
        realLen=0;
        memset(sendBuf,0,xx);
        ObexSetRequestPacket(sendBuf,&realLen,op);
        ObexSetConnectionIdHeader(sendBuf+realLen,connectionId,&realLen);
        ObexSetNameHeader(sendBuf+realLen,nameBuf,strlen(nameBuf),&realLen);
        ObexSetlLengthHeader(sendBuf+realLen,6,&realLen);
        ObexSetBodyHeader(sendBuf+realLen,"aaaaaaaaa",9,&realLen);
        ObexSetRequestPacketLen(sendBuf,len);
        send(socket,sendBuf,realLen,0);
        printf("sending package %d \n",len);

        // memset(recvBuf,0,OBEX_PACKET_MAX_LEN);
        // ieRl=recv(socket,recvBuf,OBEX_PACKET_MAX_LEN,0);
        // if(ieRl<0)
        // {
        //     printf("Target down!");
        //     return;
        // }
        // else
        //     printf("have recived \n");

        sleep(1);
        
    }
}

void load_obex_namebuf(int socket,int connectionId,int op)
{
    FILE*fp;
    char nameBuf[Maxsize];
    unsigned xx=pow(2,15)+1;
    char sendBuf[xx];
    char recvBuf[xx];
    unsigned realLen=0;
    int ieRl=0;

    struct timeval timeout = {5,0}; //set timeout 5s
    setsockopt(socket,SOL_SOCKET,SO_RCVTIMEO,(char *)&timeout,sizeof(struct timeval));

    if ((fp = fopen("dir.txt", "r")) == NULL)
    {
        printf("Error! opening file");
        // 文件指针返回 NULL 则退出
        perror("open file");       
    }

    for(int i=0;i<Maxsize;i++)
        nameBuf[i]=0;

    while(fscanf(fp,"%[^\n]",nameBuf)!=EOF)
    {

        printf("%s\n",nameBuf);
        memset(sendBuf,0,xx);
        realLen=0;

        ObexSetRequestPacket(sendBuf,&realLen,op);
        ObexSetConnectionIdHeader(sendBuf+realLen,connectionId,&realLen);
        ObexSetNameHeader(sendBuf+realLen,nameBuf,strlen(nameBuf),&realLen);
        ObexSetlLengthHeader(sendBuf+realLen,10,&realLen);
        ObexSetBodyHeader(sendBuf+realLen,"aa",2,&realLen);
        ObexSetRequestPacketLen(sendBuf,realLen);
        send(socket,sendBuf,realLen,0);

        fgetc(fp);//吸收掉最后的\n

        for(int i=0;i<Maxsize;i++)
            nameBuf[i]=0;

        memset(recvBuf,0,OBEX_PACKET_MAX_LEN);
        ieRl=recv(socket,recvBuf,OBEX_PACKET_MAX_LEN,0);
        if(ieRl<0)
        {
            if(errno==EAGAIN){
                printf("Target down!");
                return;
            }
        }

        sleep(0.5);
    }

}

int overflow_fuzz(int socket,int connectionId,int op,int times)
{
    //char nameBuf[]="\\Ebook";
    char nameBuf[Maxsize]={0};
    unsigned xx=pow(2,15)+1;
    char sendBuf[xx];
    unsigned realLen=0;
    int ieRl=0;
    fflush(stdout);
    switch (op)
    {
    case OBEX_OP_SETPATH:
        printf("[+]sending");
        fflush(stdout);
        for(int i=0;i<times;i++)
        {
            printf(".");
            fflush(stdout);
            gen_buf(1000,nameBuf,1,1);
            memset(sendBuf,0,xx);
            realLen=0;

            ObexSetRequestPacket(sendBuf,&realLen,op);
            ObexSetSetPathFlagConstant(sendBuf+realLen,&realLen);
            ObexSetConnectionIdHeader(sendBuf+realLen,connectionId,&realLen);
            ObexSetNameHeader(sendBuf+realLen,nameBuf,strlen(nameBuf),&realLen);
            ObexSetRequestPacketLen(sendBuf,realLen);
            ieRl=send(socket,sendBuf,realLen,0);
            if(ieRl<0){
                perror("\nconnection error:");
                return -1;
            }
            for(int k=0;k<Maxsize;k++)
            {nameBuf[k]=0;}

            sleep(1);
        }
        break;
    case OBEX_OP_PUT:
        break;
    default:
        break;
    }

    return 1;

}

void wirte_dir(char sendBuf[])
{
    FILE*fp;
    if ((fp = fopen("dir.txt", "a+")) == NULL)
    {
        printf("Error! opening file");
        perror("open file");       
    }

    fputs(sendBuf,fp);
    fputc('\n',fp);
    fclose(fp);

}

void load_buff(int raw,char path[],char buff[],int buf_size)
{
    FILE* fp;
    int i;

     if ((fp = fopen(path, "r")) == NULL)
    {
        printf("Error! opening file");
        perror("open file");       
    }

    for(int k=0;k<buf_size;k++)
        buff[i]=0;
    i=0;
    while(fscanf(fp,"%[^\n]",*buff)!=EOF&&i<raw)
    {
        i++;
        fgetc(fp);
    }


}


