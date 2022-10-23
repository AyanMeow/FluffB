#include "headers.h"
#include "variation.h"

#define L2_LEN 50
#define MAX_L2FIELD 0x1F
#define MAX_L2CAP_HDR 40

int l2capping(int sockfd,int size,int id)
{
	char* sbuf;
	char* rbuf;
	int ret=0;
	struct timeval timeout = {3,0}; //set timeout 3s
	setsockopt(sockfd,SOL_SOCKET,SO_RCVTIMEO,(char *)&timeout,sizeof(struct timeval));
	sbuf=malloc(size+L2CAP_CMD_HDR_SIZE);
	rbuf=malloc(size+L2CAP_CMD_HDR_SIZE); 
        
	for(int i=0;i<size;i++)
	{
		sbuf[L2CAP_CMD_HDR_SIZE + i]='A';
	}
		
	l2cap_cmd_hdr *send_cmd = (l2cap_cmd_hdr *) sbuf;
	send_cmd->ident = id; 
	send_cmd->len   = htobs(size);
	send_cmd->code = L2CAP_ECHO_REQ;
	
	if(send(sockfd, sbuf, size + L2CAP_CMD_HDR_SIZE, 0) <= 0)
        {
        	perror("\nsend():");
        }
   
        ret=recv(sockfd, rbuf, size + L2CAP_CMD_HDR_SIZE, 0);
    	if(ret<0)
    	{
       		if(errno==EAGAIN)
       		{
       			perror("\n!!!!!!!The target is dead!!!!!!!!\n");
       			return -1;
       		}
       		else
       		{
       			perror("\nrecv()");
       		}
   	}
   	else
   	{
   		printf("\ntarget is still alive \n");
   		return 1;
   	}
	   return 0;
}

int  l2hdr_fuzz(int sockfd , int size,int id,int times,unsigned int seed,int rev)
{
	char* sbuf;
	char* rbuf;
	int sizee;
	int i=1;
	int j;
	int isdead=0;
	int senderror=0;
	int maxlen=1000;
	while(1)
	{
		senderror=0;
		srand(seed+i);
		sizee=rand()%maxlen;
		sbuf=malloc(sizee+L2CAP_CMD_HDR_SIZE);
		l2cap_cmd_hdr *send_cmd = (l2cap_cmd_hdr *) sbuf;
		isdead=0;
		for(j=0;j<sizee+L2CAP_CMD_HDR_SIZE;j++)
		{
			sbuf[j]=(unsigned char)rand()%255;
		}
		fflush(stdout);
		printf("\n---------------------------------------------\n");
		printf("# round:%d \n",i);
		printf("# id:%d \n",send_cmd->ident);
		printf("# len:%d \n",send_cmd->len);
		printf("# code:%d \n",send_cmd->code);
		
		for(int k=0;k<sizee+L2CAP_CMD_HDR_SIZE;k++)
		{
			printf ("%02X ",(unsigned char)sbuf[k]);
			if((k+1)%4==0&&k!=0)
				printf("\t");
			if((k+1)%8==0&&k!=0)
				printf("\n");
		}
		printf("\n---------------------------------------------\n");
		//printf("size0=%d\n",sizee + L2CAP_CMD_HDR_SIZE);
		sizee = RandomVariation(sbuf,sizee + L2CAP_CMD_HDR_SIZE);
		//printf("size1=%d\n",sizee);
		if(send(sockfd, sbuf, sizee, 0) <= 0)
		{
			//printf("sizee=%d\n",sizee);
			//getchar();
			perror("\nsend():");
			senderror=1;
		}
		printf("send successfully\n");
		if(!senderror)
		{
			if(rev)
			{
				rbuf=malloc(sizee+L2CAP_CMD_HDR_SIZE);
				recv(sockfd,rbuf,sizee+L2CAP_CMD_HDR_SIZE,0);
				fuzzlogSR(sbuf,rbuf,1);
			}
			else
			{
				fuzzlog(sbuf,1);
			}
		}
		if((i+1)%2==0)
		{
			sleep(1);
			isdead=l2capping(sockfd,size,id);
			id++;
		}
		id++;
		i++;
		if(isdead==-1)
		{
			char filename[NAME_MAX_LEN];
			ZeroMemory(filename,NAME_MAX_LEN);
			sprintf(filename,"l2cap_%d_%d",time(0),id);
			FILE* fp=fopen(filename,"wb");
			fwrite(sbuf,1,sizee,fp);
			fclose(fp);
			return id;
		}
		sleep(1);
	}
	return id;
}