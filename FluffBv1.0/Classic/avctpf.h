#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "lib/bluetooth.h"
#include "lib/hci.h"
#include "lib/hci_lib.h"
#include "lib/l2cap.h"
#include "lib/sdp.h"

#include "variation.h"
#include<sys/timeb.h>

#define BDADDR_ANY   (&(bdaddr_t) {{0, 0, 0, 0, 0, 0}})
#define AVCTP_LENGTH 30

#if __BYTE_ORDER == __LITTLE_ENDIAN

char VERSION[]="test";

struct avctp_header {
	uint8_t ipid:1;				//invalid pid，在发送包中为0
	uint8_t cr:1;				//command/response
	uint8_t packet_type:2;		//包类型，标识是否分片/在分片中位置
	uint8_t transaction:4;		//会话标签，标示属于同一个会话
	uint16_t pid;				//与服务的uuid一致
} __attribute__ ((packed));
#define AVCTP_HEADER_LENGTH 3

#elif __BYTE_ORDER == __BIG_ENDIAN

struct avctp_header {
	uint8_t transaction:4;
	uint8_t packet_type:2;
	uint8_t cr:1;
	uint8_t ipid:1;
	uint16_t pid;
} __attribute__ ((packed));
#define AVCTP_HEADER_LENGTH 3

#else
#error "Unknown byte order"
#endif
#define AVCTP_COMMAND		0
#define AVCTP_RESPONSE		0
#define AVCTP_PACKET_SINGLE	0
#define AVCTP_VALID_PID 0

/*连接src与dst*/
static int do_connect(const bdaddr_t *src, const bdaddr_t *dst)
{
	struct sockaddr_l2 addr;
	int sk, err;

	sk = socket(PF_BLUETOOTH, SOCK_SEQPACKET, BTPROTO_L2CAP);
	if (sk < 0) {
		perror("Can't create socket");
		return -1;
	}

	memset(&addr, 0, sizeof(addr));
	addr.l2_family = AF_BLUETOOTH;
	bacpy(&addr.l2_bdaddr, src);

	if (bind(sk, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		perror("Can't bind socket");
		goto error;
	}

	memset(&addr, 0, sizeof(addr));
	addr.l2_family = AF_BLUETOOTH;
	bacpy(&addr.l2_bdaddr, dst);
	addr.l2_psm = htobs(23);

	err = connect(sk, (struct sockaddr *) &addr, sizeof(addr));
	if (err < 0) {
		perror("Unable to connect");
		goto error;
	}
	return sk;

error:
	close(sk);
	return -1;
}

//发送fuzz包
void do_avctp_send(int sk,int reciveRsp)
{
	//记录连接时间
	int count;
		time_t rawtime;
	struct tm *info;

	//打开日志文件
	FILE* fp;
	char logname[]="avctp_log";
	if(!(fp=fopen(logname,"a")))
		return;
	setbuf(fp,NULL);
	//收发包
	unsigned char recvbuf[AVCTP_LENGTH];
    unsigned char sendbuf[AVCTP_LENGTH];
	
	int randbyte,randbit;
	struct avctp_header *hdr = (void *) sendbuf;
	unsigned char Notify[] = { 0x01, 0x48, 0x00, 0x00, 0x19, 0x58, 0x31, 0x00, 0x00, 0x05, 0x0d, 0x00, 0x00, 0x00, 0x00};//预设的负载
	unsigned char Register[] = { 0x01, 0x48, 0x00, 0x00, 0x19, 0x58, 0x10, 0x00, 0x00, 0x01, 0x03};

 	ssize_t len;//包长度

	memset(sendbuf, 0, sizeof(recvbuf));
	//构造一个single包头
	hdr->packet_type = AVCTP_PACKET_SINGLE;
	hdr->cr = AVCTP_COMMAND;
	hdr->ipid = AVCTP_VALID_PID;
	hdr->pid = htons(AV_REMOTE_PROFILE_ID);
	//在包头后加入负载
	memcpy(&sendbuf[AVCTP_HEADER_LENGTH], Register, sizeof(Register));
	//记录连接时间
	time(&rawtime);
	info=localtime(&rawtime);
	fprintf(stdout,"\nconnect:%s",asctime(info));
	fprintf(fp,"\nconnect:%s",asctime(info));
	
	//持续发送包的死循环
    while(1)
    {
		//变化第randbyte字节的第（8-randbit）位
        randbyte=rand()%AVCTP_LENGTH;
		randbit=rand()%8;
//		sendbuf[randbyte]^=(0x1<<randbit);
		//发送及显示
	    len = write(sk, sendbuf, AVCTP_HEADER_LENGTH + sizeof(Register));
		fprintf(stdout,"\nsendbuf:\n");
		fprintf(fp,"\nsendbuf:\n");
		for(int i=0;i<AVCTP_LENGTH;i++)
		{
			fprintf(stdout,"\\x%.2X",(unsigned char)sendbuf[i]);
			fprintf(fp,"\\x%.2X",(unsigned char)sendbuf[i]);
		}
		fprintf(stdout,"\";\n");
		fprintf(fp,"\";\n");
		//接收及显示
		memset(recvbuf,0,sizeof(recvbuf));
	    len = read(sk, recvbuf, sizeof(recvbuf));
		if(reciveRsp)
		{
			fprintf(stdout,"recvbuf:\n");
			fprintf(fp,"recvbuf:\n");
			for(int i=0;i<AVCTP_LENGTH;i++)
			{
				fprintf(stdout,"\\x%.2X",(unsigned char)recvbuf[i]);
				fprintf(fp,"\\x%.2X",(unsigned char)recvbuf[i]);
			}
			//计入日志
			fuzzlogSR(sendbuf,recvbuf,4);
		}
		
		//检查返回包是否全0
		for(count=0;count<AVCTP_LENGTH;count++)
    	{
        	if(recvbuf[count])
            	break;
    	}
		//返回包全0，显示crush信息并结束本次连接
    	if(AVCTP_LENGTH==count)
    	{
        	fprintf(stdout,"possible crush\n");
			fprintf(fp,"\npossible crush\n");
			fuzzlog(sendbuf,4);
			close(fp);
        	return;
    	}
		//避免发包速率过快
		sleep(1);
    }
    
}

int doAVCTP(char tarAddr[ADDR_MAX_LEN],int reciveRsp)
{
    bdaddr_t src,dst;
    int sk;
    bacpy(&src, BDADDR_ANY);
	bacpy(&dst, BDADDR_ANY);
    str2ba(tarAddr, &dst);
	while(1)
	{
    	sk = do_connect(BDADDR_ANY,&dst);//连接
        if (sk < 0)
			exit(1);
    	do_avctp_send(sk,reciveRsp);//fuzz
	}
}
