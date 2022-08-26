#include "headers.h"
#include "l2capf.h"
#include "obexf.h"
#include "rfcommf.h"


int scanNearDevices(char devAddr[][ADDR_MAX_LEN],char devName[][NAME_MAX_LEN],int maxLen);
void tryFuzzing(char devAddr[ADDR_MAX_LEN]);
int scanTargetService(char devAddr[ADDR_MAX_LEN],char srvName[][NAME_MAX_LEN],int srvChannel[],int maxLen);
int doL2CAP(char tarAddr[ADDR_MAX_LEN]);
int doRFCOMM(char tarAddr[ADDR_MAX_LEN]);
int doOBEX(char tarAddr[ADDR_MAX_LEN],int channel);

int reciveRsp=0;

int main()
{
    fflush(stdout);
    int maxLen=10;
    char devName[maxLen][NAME_MAX_LEN];
    char devAddr[maxLen][ADDR_MAX_LEN];
    maxLen=scanNearDevices(devAddr,devName,maxLen);
    setbuf(stdout,NULL);
    if(0==maxLen)
    {
        printf("附近无蓝牙设备\n");
        return 0;
    }
    int tarDId=-1;
    while(tarDId<0||tarDId>=maxLen)
    {
        printf("请输入要fuzz的设备id\n");
        scanf("%d",&tarDId);
    }

    tryFuzzing(devAddr[tarDId]);

    printf("[-]session exit\n");
    return 0;
}

int scanNearDevices(char devAddr[][ADDR_MAX_LEN],char devName[][NAME_MAX_LEN],int maxLen)
{
    int devId=hci_get_route(NULL);
    int devSocket=hci_open_dev(devId);
    if(devId<0||devSocket<0)
    {
        perror("socket:");
        return -1;
    }
    inquiry_info*ii;
    ii=(inquiry_info*)malloc(maxLen*sizeof(inquiry_info));
    int len=8;
    maxLen=hci_inquiry(devId,len,maxLen,NULL,&ii,IREQ_CACHE_FLUSH);
    for(int i=0;i<maxLen;i++)
    {
        memset(devAddr[i],0,ADDR_MAX_LEN);
        ba2str(&((ii+i)->bdaddr),devAddr[i]);
        memset(devName[i],0,NAME_MAX_LEN);
        if(hci_read_remote_name(devSocket,&((ii+i)->bdaddr),NAME_MAX_LEN,devName[i],0)<0)
        {
            strcpy(devName[i],"[UNKNOWN]");
        }
        printf("[+] %d %s:%s\n",i,devName[i],devAddr[i]);
    }
    free(ii);
    hci_close_dev(devSocket);
    return maxLen;
}

void tryFuzzing(char devAddr[ADDR_MAX_LEN])
{
    fflush(stdout);
    printf("Do you want to scan service of target device?(Y/n):");
    char c='n';
    setbuf(stdin,NULL);
    scanf("%c",&c);
    int maxLen=20,len=0;
    char srvName[maxLen][NAME_MAX_LEN];
    int srvChannel[maxLen];
    if('Y'==c||'y'==c)
    {
        len=scanTargetService(devAddr,srvName,srvChannel,maxLen);
    }
    printf("\n(press any key to continue)\n");
    printf("[-] please choose one target protol(1~3):\n");
    printf("[+] 1.L2CAP\n");
    printf("[+] 2.RFCOMM\n");
    printf("[+] 3.OBEX\n");
    printf("[+] 4.SDP\n");
    printf("input:");
    int chos=-1;
    while(chos<1|chos>3)
    {
        scanf("%d",&chos);
        if(chos<1|chos>3)
        {
            printf("Illegal input! Again:");
        }
    }
    printf("\nDo you wanna recive respon packge?(Y/n)");
    char k='n';
    getchar();
    scanf("%c",&k);
    if(k=='Y'|k=='y')
    {
        reciveRsp=1;
    }
    switch (chos)
    {
    case 1:
    {
        doL2CAP(devAddr);
        break;
    }
    case 2:
    {
        doRFCOMM(devAddr);
        break;
    }
    case 3:
    {
        int c=getChannel(srvName,srvChannel,maxLen);
        if(-1==c)
        {
            printf("not obex server\n");
        }
        for(int j=1;j<20;j++)
            doOBEX(devAddr,j);
        break;
    }
    case 4:
    {
        doSDP(devAddr,100,50);
    }
    default:
    {
        break;
    }
    }
}

int scanTargetService(char devAddr[ADDR_MAX_LEN],char srvName[][NAME_MAX_LEN],int srvChannel[],int maxLen)
{
    //取得本地蓝牙设备信息
    struct hci_dev_info localDev;
    if(hci_devinfo(0,&localDev)<0)
    {
        perror("get local device info:");
        return -1;
    }
    bdaddr_t tarAddr;
    str2ba(devAddr,&tarAddr);

    //连接到远程蓝牙设备sdp服务
    sdp_session_t *pss=sdp_connect(&(localDev.bdaddr),&tarAddr,SDP_RETRY_IF_BUSY);
    if(!pss)
    {
        perror("connect to remote sdp service:");
        return -1;
    }

    //设置查询条件
    uuid_t tarUuid;
    sdp_uuid16_create(&tarUuid,PUBLIC_BROWSE_GROUP);
    uint32_t range=0x0000ffff;
    sdp_list_t *attrid,*search,*req;
    attrid=sdp_list_append(0,&range);
    search=sdp_list_append(0,&tarUuid);
    if(sdp_service_search_attr_req(pss,search,SDP_ATTR_REQ_RANGE,attrid,&req)<0)
    {
        perror("sdp service search:");
        sdp_close(pss);
        return -1;
    }
    sdp_list_free(attrid,0);
    sdp_list_free(search,0);

    //遍历查询结果
    int len=0;
    for(;req&&(len<maxLen);req=req->next)
    {
        sdp_record_t*rec=(sdp_record_t*)(req->data);
        //sdp_record_print(rec);

        //取得服务名
        memset(srvName[len],0,NAME_MAX_LEN);
        if(sdp_get_service_name(rec,srvName[len],NAME_MAX_LEN)<0)
        {
            strcpy(srvName[len],"[UNKNOWN]");
        }

        //获取可用的协议列表
        sdp_list_t *protos;
        sdp_get_access_protos(rec, &protos);
        if(protos)
        {
            //取得RFCOMM协议channel
            int channel=sdp_get_proto_port(protos,RFCOMM_UUID);
            srvChannel[len]=channel;

            printf("%d %s:%d\n",len,srvName[len],srvChannel[len]);

            len++;
        }
        
    }
    sdp_close(pss);
    return len;
}

int doL2CAP(char tarAddr[ADDR_MAX_LEN])
{
    fflush(stdout);
    printf("[-] connecting.....\n");
    int l2_sck = 0;
    int iRel  = 0;
    struct sockaddr_l2 local_l2_addr;
    struct sockaddr_l2 remote_l2_addr;
    char str[24] ={0};
    socklen_t lenth = 0;
    int size = 50;
    int sock,dev_id;
    char* send_buf;
    char* recv_buf;
    int id = 2; //不要为0
    char addr[19] = { 0 };
    char name[248] = { 0 };

    dev_id = hci_get_route(NULL);
    sock = hci_open_dev( dev_id );
    if (dev_id < 0 || sock < 0) {
        perror("opening socket");
        exit(1);
    }

    send_buf = malloc(L2CAP_CMD_HDR_SIZE + size);
    recv_buf = malloc(L2CAP_CMD_HDR_SIZE + size);

     // create l2cap raw socket
    l2_sck = socket(PF_BLUETOOTH, SOCK_RAW, BTPROTO_L2CAP); //创建L2CAP protocol的RAW Packet
    if(l2_sck < 0)
    {
        perror("\nsocket:");
        return -1;
    }
    printf("create l2cap socket successfully\n");

    //bind
    memset(&local_l2_addr, 0, sizeof(struct sockaddr_l2));
    local_l2_addr.l2_family = AF_BLUETOOTH;
    bacpy(&local_l2_addr.l2_bdaddr , BDADDR_ANY);

    iRel = bind(l2_sck, (struct sockaddr*) &local_l2_addr, sizeof(struct sockaddr_l2));
    if(iRel < 0)
    {
    perror("\nbind()");
    exit(0);
    }
    printf("bind successfully\n");

    //connect
    memset(&remote_l2_addr, 0 , sizeof(struct sockaddr_l2));
    remote_l2_addr.l2_family = AF_BLUETOOTH;
    str2ba(tarAddr, &remote_l2_addr.l2_bdaddr);
    hci_read_remote_name(sock, (const bdaddr_t *)&(remote_l2_addr.l2_bdaddr), sizeof(name), name, 0);
    printf("Connect to %s : %s\n", name,tarAddr);
    
    iRel = connect(l2_sck, (struct sockaddr*)&remote_l2_addr, sizeof(struct sockaddr_l2));
    if(iRel < 0)
    {
    perror("\nconnect()");
    exit(0);
    }

    //get local bdaddr
    lenth = sizeof(struct sockaddr_l2);
    memset(&local_l2_addr, 0, sizeof(struct sockaddr_l2));

    iRel = getsockname(l2_sck, (struct sockaddr*) &local_l2_addr, &lenth);
    if(iRel < 0)
    {
    perror("\ngetsockname()");
    exit(0);
    }
    ba2str(&(local_l2_addr.l2_bdaddr), str);
    printf("\nLocal Socket bdaddr:[%s]\n", str);
    //printf("l2ping: [%s] from [%s](data size %d) ...\n", batostr(&(ii+choose)->bdaddr), str, size);

    for (int i = 0; i < size; i++)
    send_buf[L2CAP_CMD_HDR_SIZE + i] = 0;

    l2cap_cmd_hdr *send_cmd = (l2cap_cmd_hdr *) send_buf;
    l2cap_cmd_hdr *recv_cmd = (l2cap_cmd_hdr *) recv_buf;

   if(recv(l2_sck, recv_buf, size + L2CAP_CMD_HDR_SIZE, 0) <= 0)
   {
        perror("\nrecv()");
    }
    l2hdr_fuzz(l2_sck,50,0,1000,1500,reciveRsp);
}

int doRFCOMM(char tarAddr[ADDR_MAX_LEN])
{
    int maxsize=200;
    char *buf, *savedbuf,*rbuf;
	//struct hidp_conndel_req addr;
	int sock, i, size;
	int crash_count=0, savedsize;
    int maxcrash=2;
	sock = socket(PF_BLUETOOTH,SOCK_STREAM,BTPROTO_L2CAP);
	if (sock<=0)
	{
		perror("socket");
		exit(EXIT_FAILURE);
	}

	struct sockaddr_l2 addr_remote;
    memset(&addr_remote,0,sizeof(addr_remote));
    addr_remote.l2_family=PF_BLUETOOTH;
    addr_remote.l2_psm=RFCOMM_PSM;
    str2ba(tarAddr,(bdaddr_t*)&addr_remote.l2_bdaddr);

    if(0!=connect(sock,(struct sockaddr*)&addr_remote,sizeof(addr_remote)))
    {
        perror("connect");
		exit(EXIT_FAILURE);
    }

	if(!(savedbuf = (char *) malloc ((int) maxsize + 1))) {
		perror("malloc");
		exit(EXIT_FAILURE);
	}
    unsigned ind=0;
     srand(time(0));
	while(1)		// Initite loop (ctrl-c to stop...)
	{	
        sleep(1);
		size=rand() % maxsize;
		if(size == 0) 
			size=1;
		if(!(buf = (char *) malloc ((int) size + 1))) {
			perror("malloc");
			exit(EXIT_FAILURE);
		}
        if(reciveRsp)
        {
            if(!(rbuf = (char *) malloc ((int) size + 1))) {
			perror("malloc");
			exit(EXIT_FAILURE);
		}
        }

		bzero(buf, size);
		for(i=0 ; i<size ; i++)	
			buf[i] = rand();
		rcCommandFrame*cFrame=(rcCommandFrame*)buf;
        cFrame->address.EA=1;
        cFrame->address.CR=1;
        cFrame->address.D=0;
        cFrame->address.ServerChannel=0;
        cFrame->control.init=RC_CONTROL_SABM;
        cFrame->control.PF=1;
        cFrame->length.EA=1;
        cFrame->length.length=0;
        cFrame->fcs=calc_fcs(&cFrame->address,RC_FCS_SIZE_COMMAND);
		putchar('.');
		fflush(stdout);
		size=RandomVariation(buf,size);
        printf("%d:%d\n",++ind,size);
		if(send(sock, buf, size, 0) <= 0)
		{
			crash_count++;
			fprintf(stdout, "\n%s BT stack may have crashed. This device seems to be vulnerable to buggy packets.\n", tarAddr);
			fprintf(stdout, "Please, ensure that the device has really crashed doing a bt scan for instance.\n");
			fprintf(stdout, "\t----------------------------------------------------\n");
			fprintf(stdout, "\tHost\t\t%s\n", tarAddr);
			fprintf(stdout, "\tPacket size\t%d\n", savedsize);
			fprintf(stdout, "\t----------------------------------------------------\n");
			fprintf(stdout, "\tPacket dump\n\t");
			for(i=0 ; i<savedsize ; i++)
			{
				fprintf(stdout, "0x%.2X ", (unsigned char) savedbuf[i]);
				if( (i%30) == 29)
					fprintf(stdout, "\n\t");
			}
			fprintf(stdout, "\n\t----------------------------------------------------\n");

			fprintf(stdout, "char replay_buggy_packet[]=\"");
			for(i=0 ; i<savedsize ; i++)
			{
				fprintf(stdout, "\\x%.2X", (unsigned char) savedbuf[i]);
			}
			fprintf(stdout, "\";\n");

			if((crash_count == maxcrash) && (maxcrash != 0) && (maxcrash >= 0))
			{
				free(buf);
				free(savedbuf);
				exit(EXIT_SUCCESS);
			}
			
		}
        if(reciveRsp)
        {
            recv(sock,rbuf,size,0);
            fuzzlogSR(buf,rbuf,2);
        }
        else
        {
            fuzzlog(buf,2);
        }
		memcpy(savedbuf, buf, size);	// Get the previous packet, not this one...
		savedsize = size;
		free(buf);
	}
}

int doOBEX(char tarAddr[ADDR_MAX_LEN],int channel)
{
    //初始化发送缓冲区
    char sendBuf[OBEX_PACKET_MAX_LEN];
    char recvBuf[OBEX_PACKET_MAX_LEN];
    unsigned int realLen;

    srand(time(0));
    int ind=0;
    while(1)
    {
        fflush(stdout);
        int s=socket(PF_BLUETOOTH,SOCK_STREAM,BTPROTO_RFCOMM);

        struct timeval timeo={3,0};
        socklen_t l=sizeof(timeo);
        timeo.tv_sec=30;
        setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &timeo, l);
        if(s<0)
        {
            perror("socket:");
            return -1;
        }
        struct sockaddr_rc addr;
        addr.rc_family=AF_BLUETOOTH;
        addr.rc_channel=channel;
        str2ba(tarAddr,&(addr.rc_bdaddr));
        if(0!=connect(s,(const struct sockaddr*)(&addr),sizeof(addr)))
        {
            perror("connect:");
            return -1;
        }

        char sendBuf[OBEX_PACKET_MAX_LEN];
        char recvBuf[OBEX_PACKET_MAX_LEN];
        unsigned int realLen;

        // 发送连接请求
        memset(sendBuf,0,OBEX_PACKET_MAX_LEN);
        realLen=0;
        ObexSetRowPacket(sendBuf,OBEX_PACKET_MAX_LEN,&realLen,OBEX_OP_CONNECT);
        ObexSetCountHeader(sendBuf+realLen,1,&realLen);
        ObexSetRowPacketLen(sendBuf,realLen);
        send(s,sendBuf,realLen,0);

        struct timeval timeout = {3,0}; //set timeout 3s
        setsockopt(s,SOL_SOCKET,SO_RCVTIMEO,(char *)&timeout,sizeof(struct timeval));

        //接收数据,判断是否连接成功
        memset(recvBuf,0,OBEX_PACKET_MAX_LEN);
        recv(s,recvBuf,OBEX_PACKET_MAX_LEN,0);
        ObexSuccessPacket*successPacket=(ObexSuccessPacket*)recvBuf;
        if(OBEX_OP_SUCCESS==successPacket->op||OBEX_OP_SUCCESS2==successPacket->op)
        {
            printf("[+] obex connection succeed, channel:%d\n",channel);
        }
        else
        {
            printf("[!] obex connection failed\n");
            return -1;
        }
        //取得连接id
        ObexConnectionIdHeader*connectionIdHeader=(ObexConnectionIdHeader*)(recvBuf+OBEX_ROWPACKET_SIZE);
        int connectionId=getUint32FromChar(connectionIdHeader->c3,connectionIdHeader->c2,connectionIdHeader->c1,connectionIdHeader->c0);
        
        int nameLen=rand()%512;
        char nameBuf[nameLen];
        for(int i=0;i<nameLen;i++)
        {
            nameBuf[i]=rand();
        }
        nameBuf[nameLen-4]='.';
        nameBuf[nameLen-3]='t';
        nameBuf[nameLen-2]='x';
        nameBuf[nameLen-1]='t';

        memset(sendBuf,0,nameLen);
        realLen=0;

        ObexSetRequestPacket(sendBuf,&realLen,OBEX_OP_PUT);
        ObexSetConnectionIdHeader(sendBuf+realLen,connectionId,&realLen);
        ObexSetNameHeader(sendBuf+realLen,nameBuf,nameLen,&realLen);
        ObexSetlLengthHeader(sendBuf+realLen,2,&realLen);
        ObexSetBodyHeader(sendBuf+realLen,"AA",2,&realLen);
        ObexSetRequestPacketLen(sendBuf,realLen);
        realLen=RandomVariation(sendBuf,realLen);
        printf("%d:%d\n",++ind,realLen);
        if(-1== send(s,sendBuf,realLen,0))
        {
            perror("send");
            break;
        }
        if(reciveRsp)
        {
            recv(s,recvBuf,50,0);
            fuzzlogSR(sendBuf,recvBuf,3);
        }
        else
        {
            fuzzlog(sendBuf,3);
        }
        setsockopt(s,SOL_SOCKET,SO_RCVTIMEO,(char *)&timeout,sizeof(struct timeval));
        recv(s,recvBuf,OBEX_PACKET_MAX_LEN,0);

        //发送PUT结束包
        memset(sendBuf,0,OBEX_PACKET_MAX_LEN);
        realLen=0;
        ObexSetRequestPacket(sendBuf,&realLen,OBEX_OP_PUT|OBEX_FLAG_FINAL);
        ObexSetConnectionIdHeader(sendBuf+realLen,connectionId,&realLen);
        ObexSetEndOfBodeHeader(sendBuf+realLen,"",0,&realLen);
        ObexSetRequestPacketLen(sendBuf,realLen);
        send(s,sendBuf,realLen,0);
        setsockopt(s,SOL_SOCKET,SO_RCVTIMEO,(char *)&timeout,sizeof(struct timeval));
        recv(s,recvBuf,OBEX_PACKET_MAX_LEN,0);

        if(reciveRsp)
        {
            recv(s,recvBuf,50,0);
            fuzzlogSR(sendBuf,recvBuf,3);
        }
        else
        {
            fuzzlog(sendBuf,3);
        }

        //文件发送完成，发送断开连接包
        memset(sendBuf,0,OBEX_PACKET_MAX_LEN);
        realLen=0;
        ObexSetRequestPacket(sendBuf,&realLen,OBEX_OP_DISCONNECT|OBEX_FLAG_FINAL);
        ObexSetConnectionIdHeader(sendBuf+realLen,connectionId,&realLen);
        ObexSetRequestPacketLen(sendBuf,realLen);
        send(s,sendBuf,realLen,0);
        setsockopt(s,SOL_SOCKET,SO_RCVTIMEO,(char *)&timeout,sizeof(struct timeval));
        recv(s,recvBuf,OBEX_PACKET_MAX_LEN,0);

        if(reciveRsp)
        {
            recv(s,recvBuf,50,0);
            fuzzlogSR(sendBuf,recvBuf,3);
        }
        else
        {
            fuzzlog(sendBuf,3);
        }
        
        close(s);
        sleep(2);
    }
}


int doSDP(char tarAddr[ADDR_MAX_LEN],int maxsize,int eachtimes)
{
    struct hci_dev_info localDev;
    if(hci_devinfo(0,&localDev)<0)
    {
        perror("get local device info:");
        return -1;
    }

    bdaddr_t remote;
    str2ba(tarAddr,&remote);

    for (int i = 0; i < eachtimes; i++)
    {
        sdp_session_t *sdp_auto=sdp_connect(&(localDev.bdaddr),&remote,SDP_RETRY_IF_BUSY);

        char *sendbuff,*recvbuff;
        sendbuff=malloc(maxsize);
        recvbuff=malloc(maxsize);

        srand((int)time(NULL));
        uuid_t *uuids;
        unsigned short len=rand();
        uuids=(uuid_t*)malloc(len*sizeof(uuid_t));
        for (int j = 0; j < len; j++)
        {
            uuid_generate_random(uuids[j]);
        }
        
        uuid_t tarUuid;
        uuid_generate_random(tarUuid);

        int totalsize;
        setSDP_SERVICE_SEARCH_REQ(sendbuff,sdp_auto->tid,len,uuids,(unsigned short)rand(),&totalsize);

        if(send(sdp_auto->sock,sendbuff,totalsize,0)<=0)
        {
            perror("socket:");
        }

        if(reciveRsp)
        {
            recv(sdp_auto->sock,recvbuff,maxsize,0);
            fuzzlogSR(sendbuff,recvbuff,4);
        }
        else
        {
            fuzzlog(sendbuff,4);
        }

        sleep(1);
    }
    
    for (int i = 0; i < eachtimes; i++)
    {
        sdp_session_t *sdp_auto=sdp_connect(&(localDev.bdaddr),&remote,SDP_RETRY_IF_BUSY);

        char *sendbuff,*recvbuff;
        sendbuff=malloc(maxsize);
        recvbuff=malloc(maxsize);

        srand((int)time(NULL));

        int maxat=(unsigned int)rand();
        unsigned int *atbs;
        atbs=(unsigned int*)malloc(maxat*sizeof(unsigned int));
        for (int j = 0; j < maxat; j++)
        {
            atbs[j]=(unsigned int)rand();
        }
        
        int totalsize;
        setSDP_SERVICE_ATTR_REQ(sendbuff,sdp_auto->tid,(unsigned int)rand(),maxat,atbs,&totalsize);

         if(send(sdp_auto->sock,sendbuff,totalsize,0)<=0)
        {
            perror("socket:");
        }

        if(reciveRsp)
        {
            recv(sdp_auto->sock,recvbuff,maxsize,0);
            fuzzlogSR(sendbuff,recvbuff,4);
        }
        else
        {
            fuzzlog(sendbuff,4);
        }

        sleep(1);
    }

    return 1;
}