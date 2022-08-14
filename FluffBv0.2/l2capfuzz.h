#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>
#include <sys/types.h>         
#include <sys/socket.h>
#include <poll.h>
#include <bluetooth/l2cap.h>
#include <errno.h>

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
		sbuf[L2CAP_CMD_HDR_SIZE + i]='A';
		
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
}

int  l2hdr_fuzz(int sockfd , int size,int id,int times,unsigned int seed)
{
	char* sbuf;
	int sizee;
	int i=1;
	int j;
	int isdead=0;
        while(1)
        {
        	srand(seed+i);
        	sizee=rand()%4500;
        	sbuf=malloc(sizee+L2CAP_CMD_HDR_SIZE);
		l2cap_cmd_hdr *send_cmd = (l2cap_cmd_hdr *) sbuf;
        	isdead=0;
        	for(j=0;j<sizee+L2CAP_CMD_HDR_SIZE;j++)
			sbuf[j]=(unsigned char)rand()%255;
		//while(j<size)
			//{sbuf[L2CAP_CMD_HDR_SIZE + j]=0x00;j++;}
		//send_cmd->ident = id; 
        	//send_cmd->len   = sizee;
        	//send_cmd->code = (rand())%25+1;
        	//send_cmd->len=htobs(0x0008);
        	//send_cmd->code=L2CAP_CONF_REQ;
        	//l2cap_conf_req *conf_cmd = (l2cap_conf_req *) (sbuf+sizeof(l2cap_cmd_hdr));
        	//conf_cmd->dcid=htobs(0x0040);
        	
        	printf("\n---------------------------------------------\n");
        	printf("# round:%d \n",i);
        	printf("# id:%d \n",send_cmd->ident);
        	printf("# len:%d \n",send_cmd->len);
        	printf("# code:%d \n",send_cmd->code);
        	
        	//for(int k=0;k<send_cmd->len + L2CAP_CMD_HDR_SIZE;k++)
        	for(int k=0;k<sizee+L2CAP_CMD_HDR_SIZE;k++)
        	{
            	printf ("%02X ",(unsigned char)sbuf[k]);
            	if((k+1)%4==0&&k!=0)
                	printf("\t");
            	if((k+1)%8==0&&k!=0)
                	printf("\n");
        	}
        	printf("\n---------------------------------------------\n");
        	
        	if(send(sockfd, sbuf, sizee + L2CAP_CMD_HDR_SIZE, 0) <= 0)
        	{
        		perror("\nsend():");
        	}
        	if((i+1)%2==0){
        		sleep(0.5);
        		isdead=l2capping(sockfd,size,id);
        		id++;}
        	id++;
        	i++;
        	if(isdead==-1)
        		return id;
        	sleep(0.5);
        }
	return id;
}

int l2hdr_overflow(int sockfd,int size)
{
	int len=1;
	int code;
	int id;
	char *send_buff;
	send_buff=malloc(size+L2CAP_CMD_HDR_SIZE);
	for(len=0;len<size+L2CAP_CMD_HDR_SIZE;len++)
		send_buff[len]='A';
	l2cap_cmd_hdr *send_cmd = (l2cap_cmd_hdr *) send_buff;
	for(len=0;len<=MAX_L2CAP_HDR;len++)
	{
		for(code=0;code<=MAX_L2FIELD;code++)
		{
			for(id=0;id<=MAX_L2FIELD;id++)
			{
				send_cmd->code=code;
				send_cmd->ident=id;
				send_cmd->len=htobs(len);
				
				printf("\n---------------------------------------------\n");
				printf("# id:%d \n",send_cmd->ident);
				printf("# len:%d \n",send_cmd->len);
				printf("# code:%d \n",send_cmd->code);
				
				//for(int k=0;k<send_cmd->len + L2CAP_CMD_HDR_SIZE;k++)
				for(int k=0;k<size+L2CAP_CMD_HDR_SIZE;k++)
				{
			    	printf ("%02X ",(unsigned char)send_buff[k]);
			    	if((k+1)%4==0&&k!=0)
					printf("\t");
			    	if((k+1)%8==0&&k!=0)
					printf("\n");
				}
				printf("\n---------------------------------------------\n");
				
				if(send(sockfd, send_buff, size+L2CAP_CMD_HDR_SIZE, 0) <= 0)
				{
					perror("\nsend():");
				}
				
				sleep(0.5);
				if(l2capping(sockfd,size,id)==-1)
					return -1;
				sleep(0.5);
				
			}
		}
	}
	printf("\ncomplete!\n");
	return 1;
}